"""Actual registry/agent collection: no preview may stand in for execution data."""
from __future__ import annotations

import asyncio
import json
import re
import threading
import tracemalloc
from types import SimpleNamespace

import pytest
from maverick import tool_result_artifacts as artifacts
from maverick import tool_result_stream as stream
from maverick.agent import Agent, unframe_tool_output
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.paths import tenant_scope
from maverick.run_outcome import owned_task, task_stop
from maverick.tool_results import ToolOutcome, ToolResultState, classify_tool_result
from maverick.tools import Tool, ToolRegistry


@pytest.fixture(autouse=True)
def isolated_artifacts(tmp_path, monkeypatch):
    from maverick.tenant import kms

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_KMS_KEK", "18" * 32)  # synthetic test key
    monkeypatch.setattr(kms, "_dek_cache", {})


def registry(fn, name="producer"):
    reg = ToolRegistry()
    reg.register(Tool(name=name, description="test", input_schema={}, fn=fn))
    return reg


def agent_boundary(monkeypatch, fn, *, shield=None):
    agent = Agent.__new__(Agent)
    agent.ctx = SimpleNamespace(goal_id=71, budget=Budget(), blackboard=Blackboard())
    agent.name, agent.role, agent.model = "test", "researcher", "test-model"
    agent.tools = registry(fn)
    agent.tools._principal = "user:alice"
    rows, seen = [], []
    agent.tools.set_chunk_listener(lambda name, chunk: seen.append((name, chunk)))

    async def guarded(call, **kw):
        return await call()

    async def hooks(_ctx):
        return True

    monkeypatch.setattr("maverick.hooks.dispatch", hooks)
    monkeypatch.setattr("maverick.agent._tool_result_limit", lambda _model: 512)
    agent._await_wall_clock_guarded = guarded
    agent._audit_tool_event = lambda kind, **payload: rows.append((kind, payload)) or True
    agent._loop_guard_note = lambda *a: ""
    agent._maybe_seal = lambda *a: None

    async def run():
        return await agent._run_dispatched_tool("producer", {"api_key": "not-forwarded"},  # pragma: allowlist secret - synthetic tool argument fixture
            shield=shield, quarantine=None, call_id="test-call", call_commitment="test-digest",
            principal="user:alice")

    return agent, run, rows, seen


@pytest.mark.asyncio
async def test_agent_dispatch_binds_explicit_capability_for_nested_flow(monkeypatch):
    from maverick import capability, tool_authz
    monkeypatch.setattr(capability, "capability_enforced", lambda: False)
    monkeypatch.setattr(tool_authz, "_record_denial", lambda *a, **k: None)
    agent, _, _, _ = agent_boundary(
        monkeypatch,
        lambda _args: tool_authz.authorize("http_fetch", {}, origin="flow") or "ALLOWED",
    )
    output = await agent._run_dispatched_tool(
        "producer", {}, shield=None, quarantine=None, call_id="call",
        call_commitment="digest", principal="user:alice", capability_active=True,
    )
    assert "capability enforcement" in output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("state", "content", "is_error", "disposition"),
    [
        (ToolResultState.SUCCEEDED, "ERROR is a document title", False, "completed"),
        (ToolResultState.FAILED, "the operation failed", True, "tool_error"),
        (ToolResultState.INDETERMINATE, "receipt not available", True, "execution_unknown"),
    ],
)
async def test_explicit_tool_state_survives_screening_and_provider_boundary(
    monkeypatch, state, content, is_error, disposition,
):
    agent, run, rows, _seen = agent_boundary(monkeypatch, lambda _args: ToolOutcome(state, content))
    output = await run()

    assert classify_tool_result(output) is state
    assert content in output
    assert rows[-1][1]["disposition"] == disposition
    wire = Agent._make_tool_result("call", output)
    assert type(wire["content"]) is str
    assert wire.get("is_error", False) is is_error


@pytest.mark.asyncio
async def test_explicit_tool_state_is_not_lost_in_string_only_cache(monkeypatch):
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    monkeypatch.setattr("maverick.cache.tool.cacheable", lambda _tool: True)
    calls = []

    def read(_args):
        calls.append(1)
        return ToolOutcome(ToolResultState.SUCCEEDED, "ERROR is ordinary text")

    reg = ToolRegistry()
    reg.register(Tool(name="typed_read", description="test", input_schema={}, fn=read,
                      parallel_safe=True))
    first = await reg.run("typed_read", {})
    second = await reg.run("typed_read", {})
    assert classify_tool_result(first) is ToolResultState.SUCCEEDED
    assert classify_tool_result(second) is ToolResultState.SUCCEEDED
    assert calls == [1, 1]

    plain_calls = []
    reg.register(Tool(name="untyped_read_control", description="test", input_schema={},
                      fn=lambda _args: plain_calls.append(1) or "plain", parallel_safe=True))
    assert await reg.run("untyped_read_control", {}) == "plain"
    assert await reg.run("untyped_read_control", {}) == "plain"
    assert plain_calls == [1]


@pytest.mark.asyncio
async def test_workspace_read_preserves_content_starting_with_status_marker(tmp_path):
    from maverick.sandbox import LocalBackend
    from maverick.tools.fs import read_file

    (tmp_path / "note.txt").write_text("INDETERMINATE is a valid word", encoding="utf-8")
    reg = ToolRegistry()
    reg.register(read_file(LocalBackend(workdir=tmp_path)))

    output = await reg.run("read_file", {"path": "note.txt"})
    assert output == "INDETERMINATE is a valid word"
    assert classify_tool_result(output) is ToolResultState.SUCCEEDED
    assert "is_error" not in Agent._make_tool_result("call", output)

    missing = await reg.run("read_file", {"path": "missing.txt"})
    assert classify_tool_result(missing) is ToolResultState.FAILED


@pytest.mark.asyncio
async def test_split_secret_screened_before_listener_and_complete_artifact(monkeypatch):
    secret = "sk-" + "A" * 40  # pragma: allowlist secret - synthetic split-token construction
    full = "customer row\n" * 4000 + secret + "\nTAIL_VALUE_92817"

    def producer(_args):
        yield full[:48002]
        yield full[48002:]

    scanned = []
    shield = SimpleNamespace(scan_output=lambda value: scanned.append(value) or SimpleNamespace(allowed=True))
    agent, run, rows, seen = agent_boundary(monkeypatch, producer, shield=shield)
    output = await run()
    assert scanned == [full]
    assert secret not in output and secret not in str(seen)
    assert "not-forwarded" not in str(seen)
    assert rows[-1][1]["disposition"] == "completed"
    assert len(output) < 1500 and "truncated" in output
    ref = re.search(r"artifact_id=([a-f0-9]{64})", output)[1]
    complete = artifacts.read_complete(ref, goal_id=71, principal="user:alice")
    assert complete.endswith("TAIL_VALUE_92817") and secret not in complete
    assert complete == "".join(c for _n, c in seen if not c.startswith("[Buffering"))
    reader = artifacts.read_tool_result(goal_id=71, principal="user:alice")
    pages, cursor = [], 0
    while True:
        page = json.loads(reader.fn({"artifact_id": ref, "offset": cursor, "limit": 1000}))
        pages.append(page["text"])
        if not page["has_more"]:
            break
        cursor = page["next_offset"]
    assert "".join(pages) == complete
    assert secret.encode() not in (artifacts._root() / f"{ref}.bin").read_bytes()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["blocked", "scanner", "redactor", "terminal"])
async def test_no_producer_content_reaches_listener_on_failed_delivery(monkeypatch, failure):
    def producer(_args):
        yield "PRIVATE_"
        yield "CONTENT"

    def scan(value):
        assert value == "PRIVATE_CONTENT"
        if failure == "scanner":
            raise RuntimeError("scanner unavailable")
        return SimpleNamespace(allowed=failure != "blocked", severity="high", reasons=["policy"])

    agent, run, rows, seen = agent_boundary(monkeypatch, producer, shield=SimpleNamespace(scan_output=scan))
    if failure == "redactor":
        def broken(_text):
            raise RuntimeError("redactor unavailable")
        monkeypatch.setattr("maverick.safety.secret_detector.redact", broken)
    if failure == "terminal":
        agent._audit_tool_event = lambda *a, **kw: False
    output = await run()
    assert "PRIVATE" not in output and "PRIVATE" not in str(seen)
    if failure != "terminal":
        assert rows[-1][1]["status"] == "ok"  # effect status survives delivery failure


@pytest.mark.asyncio
@pytest.mark.parametrize("observer", ["missing", "throwing"])
async def test_optional_observer_cannot_reclassify_screened_completion(monkeypatch, observer):
    calls, observed = [], []
    secret = "sk-" + "A" * 40  # pragma: allowlist secret - repeated synthetic fixture

    async def execute(_name, _args):
        calls.append(1)
        return "business result " + secret

    def deliver(_name, content):
        observed.append(content)
        raise RuntimeError("observer unavailable")

    agent, run, rows, _seen = agent_boundary(monkeypatch, lambda _: "unused")
    agent.tools = SimpleNamespace(run=execute)
    if observer == "throwing":
        agent.tools.deliver_screened = deliver
    result = await run()
    assert calls == [1] and "business result" in unframe_tool_output(result)
    assert secret not in result and secret not in str(observed)
    assert len(rows) == 1 and rows[0][1]["disposition"] == "completed"
    assert rows[0][1]["status"] == "ok"


@pytest.mark.asyncio
async def test_quota_failure_closes_producer_and_is_not_retried(monkeypatch):
    monkeypatch.setattr(stream, "MAX_RESULT_BYTES", 1024)
    calls, closed = [], []

    def producer(_args):
        calls.append(1)
        try:
            yield "x" * 800
            yield "y" * 800
        finally:
            closed.append(1)

    reg = registry(producer, "read_file")
    output = await reg.run("read_file", {})
    assert output.startswith("INDETERMINATE:") and output.tool_execution_unknown
    assert calls == closed == [1]


@pytest.mark.asyncio
async def test_partial_timeout_is_unknown_even_for_retry_safe_tool():
    calls = []

    async def producer(_args):
        calls.append(1)
        yield "partial"
        raise TimeoutError("network response timed out after receiving data")

    reg = registry(producer, "read_file")
    output = await reg.run("read_file", {})
    assert output.tool_execution_unknown and calls == [1]
    assert "partial" not in output.lower().replace("partial output was withheld", "")


@pytest.mark.asyncio
async def test_cancelled_sync_worker_remains_owned_until_physical_exit():
    started, release, closed = threading.Event(), threading.Event(), threading.Event()

    def producer(_args):
        try:
            started.set()
            release.wait(3)
            yield "never delivered"
        finally:
            closed.set()

    task = owned_task(stream.execute_tool(producer, {}))
    try:
        for _ in range(200):
            if started.is_set():
                break
            await asyncio.sleep(0.005)
        assert started.is_set()
        task.cancel()
        with pytest.raises(asyncio.CancelledError) as caught:
            await task
        assert task_stop(task, caught.value).tool_execution_unknown
        assert stream.pending_tool_workers() == 1
    finally:
        release.set()
        for _ in range(200):
            if stream.pending_tool_workers() == 0:
                break
            await asyncio.sleep(0.005)
    assert closed.is_set() and stream.pending_tool_workers() == 0


@pytest.mark.asyncio
async def test_async_cancellation_closes_producer():
    started, closed = asyncio.Event(), []

    async def producer(_args):
        try:
            yield "first"
            started.set()
            await asyncio.Event().wait()
        finally:
            closed.append(1)

    task = asyncio.create_task(stream.execute_tool(producer, {}))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert closed == [1]


@pytest.mark.asyncio
async def test_resistant_async_producer_is_owned_after_bounded_cancellation(monkeypatch):
    started, release = asyncio.Event(), asyncio.Event()

    async def producer(_args):
        started.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            await release.wait()  # deliberately noncooperative third-party code
        return "late content"

    task = owned_task(stream.execute_tool(producer, {}))
    await started.wait()
    try:
        task.cancel()
        with pytest.raises(asyncio.CancelledError) as caught:
            await asyncio.wait_for(task, timeout=2)
        assert task_stop(task, caught.value).tool_execution_unknown
        assert stream.pending_tool_invocations() == 1
        monkeypatch.setattr(stream, "MAX_WORKERS", 1)
        with pytest.raises(stream.ToolWorkerCapacity):
            await stream.execute_tool(lambda _: pytest.fail("not admitted"), {})
    finally:
        release.set()
        for _ in range(100):
            if stream.pending_tool_invocations() == 0:
                break
            await asyncio.sleep(0.005)
    assert stream.pending_tool_invocations() == 0


@pytest.mark.asyncio
async def test_async_close_timeout_is_unknown_and_cleanup_remains_owned(monkeypatch):
    release = asyncio.Event()

    class Iterator:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

        async def aclose(self):
            await release.wait()

    reg = registry(lambda _: Iterator(), "read_file")
    try:
        output = await asyncio.wait_for(reg.run("read_file", {}), timeout=2)
        assert output.tool_execution_unknown and stream.pending_tool_invocations() == 1
        monkeypatch.setattr(stream, "MAX_WORKERS", 1)
        with pytest.raises(stream.ToolWorkerCapacity):
            await stream.execute_tool(lambda _: pytest.fail("cleanup owns capacity"), {})
    finally:
        release.set()
        for _ in range(100):
            if stream.pending_tool_invocations() == 0:
                break
            await asyncio.sleep(0.005)
    assert stream.pending_tool_invocations() == 0


@pytest.mark.asyncio
async def test_connector_attempt_metadata_survives_collection():
    from maverick.connector_attempts import ConnectorAttempt, ConnectorResult

    attempt = ConnectorAttempt(request_id="test", attempt=1, operation="plugin", outcome_unknown=True)
    result = ConnectorResult("INDETERMINATE: plugin effect unknown", attempt)
    assert await stream.execute_tool(lambda _: result, {}) is result


def test_multibyte_quota_never_slices_execution_value(monkeypatch):
    monkeypatch.setattr(stream, "MAX_RESULT_BYTES", 1024)
    sink = stream.ResultSink()
    with pytest.raises(stream.ToolOutputLimit):
        sink.append("😀" * 300)
    assert sink.retained_bytes == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_cleanup_failure_never_replaces_budget_stop(asynchronous):
    from maverick.budget import BudgetExceeded

    class Iterator:
        def __iter__(self):
            return self

        def __next__(self):
            raise BudgetExceeded("stop")

        def close(self):
            raise RuntimeError("cleanup failed")

    class AsyncIterator:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise BudgetExceeded("stop")

        async def aclose(self):
            raise RuntimeError("cleanup failed")

    with pytest.raises(BudgetExceeded) as caught:
        await registry(lambda _: AsyncIterator() if asynchronous else Iterator()).run("producer", {})
    assert caught.value.tool_execution_unknown


def test_many_chunks_have_bounded_retained_memory():
    tracemalloc.start()
    try:
        sink = stream.ResultSink()
        for _ in range(8192):
            sink.append("a" * 1024)
        assert sink.retained_bytes == 8 * 1024 * 1024
        result = sink.finish()
        _current, peak = tracemalloc.get_traced_memory()
        assert len(result) == 8 * 1024 * 1024 and sink.retained_bytes == 0
        assert peak < 22 * 1024 * 1024
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("change", ["goal", "owner", "tenant", "missing", "corrupt", "expired"])
def test_artifact_authority_custody_and_expiry(change, monkeypatch):
    with tenant_scope(tenant="customer-a"):
        ref = artifacts.publish("complete business data", goal_id=1, principal="alice", tool="query")
        path = artifacts._root() / (ref["artifact_id"] + ".bin")
        if change == "missing":
            path.unlink()
        if change == "corrupt":
            path.write_bytes(b"corrupt")
        if change == "expired":
            monkeypatch.setattr(artifacts.time, "time", lambda: ref["expires_at"] + 1)
        with tenant_scope(tenant="customer-b" if change == "tenant" else "customer-a"):
            with pytest.raises(artifacts.ToolArtifactError):
                artifacts.read_complete(ref["artifact_id"], goal_id=2 if change == "goal" else 1,
                                        principal="bob" if change == "owner" else "alice")


def test_artifact_quota_does_not_evict_live_result(monkeypatch):
    monkeypatch.setattr(artifacts, "MAX_TENANT_FILES", 1)
    ref = artifacts.publish("first", goal_id=1, principal="alice", tool="query")
    with pytest.raises(artifacts.ToolArtifactError, match="quota"):
        artifacts.publish("second", goal_id=1, principal="alice", tool="query")
    assert artifacts.read_complete(ref["artifact_id"], goal_id=1, principal="alice") == "first"


def _approve_code(monkeypatch):
    """A person approved this script and its declared calls (code_exec permit)."""
    from contextlib import nullcontext

    from maverick.tools import code_exec

    async def permit(_agent, _code, _declared):
        return "approved-permit"

    monkeypatch.setattr(code_exec, "_request_code_permit", permit)
    monkeypatch.setattr(code_exec, "consume_operation_consent", lambda _permit: nullcontext())


@pytest.mark.asyncio
async def test_programmatic_execution_receives_full_screened_tail(monkeypatch):
    from maverick.tools.code_exec import code_exec_tool

    _approve_code(monkeypatch)

    full = "row,42\n" * 8000 + "CRITICAL_FINAL_ROW"
    agent, run, _rows, _seen = agent_boundary(monkeypatch, lambda _: full)
    agent.ctx.sandbox = object()
    captured = []

    async def tool(_name, _args):
        return await run()

    agent._run_tool = tool
    monkeypatch.setattr("maverick.tools.code_exec.sandbox_run",
                        lambda *a, **kw: captured.append(kw["stdin"]) or (0, "ok", ""))
    result = await code_exec_tool(agent).fn({"code": "print('ok')", "tool_calls": [{"name": "producer"}]})
    assert result == "ok"
    assert "CRITICAL_FINAL_ROW" in captured[0] and "truncated" not in captured[0]
    assert "artifact_id" not in captured[0] and full == unframe_tool_output(await _full(run))


async def _full(run):
    with stream.execution_output_scope():
        return await run()


@pytest.mark.asyncio
@pytest.mark.parametrize("state, expected_execution", [
    (ToolResultState.SUCCEEDED, True),
    (ToolResultState.INDETERMINATE, False),
])
async def test_programmatic_execution_respects_explicit_result_state(monkeypatch, state, expected_execution):
    from maverick.tools.code_exec import code_exec_tool

    _approve_code(monkeypatch)
    agent, run, _rows, _seen = agent_boundary(
        monkeypatch, lambda _: ToolOutcome(state, "INDETERMINATE: input content"),
    )
    agent.ctx.sandbox = object()
    captured = []

    async def tool(_name, _args):
        return await run()

    agent._run_tool = tool
    monkeypatch.setattr("maverick.tools.code_exec.sandbox_run",
                        lambda *a, **kw: captured.append(kw["stdin"]) or (0, "ok", ""))
    result = await code_exec_tool(agent).fn({"code": "print('ok')", "tool_calls": [{"name": "producer"}]})
    assert bool(captured) is expected_execution
    if expected_execution:
        assert result == "ok" and "INDETERMINATE: input content" in captured[0]
    else:
        assert result.startswith("INDETERMINATE:")


@pytest.mark.asyncio
async def test_programmatic_aggregate_quota_never_runs_partial_script(monkeypatch):
    from maverick.tools.code_exec import code_exec_tool

    _approve_code(monkeypatch)

    monkeypatch.setattr(stream, "MAX_RESULT_BYTES", 1024)
    agent, run, rows, _seen = agent_boundary(monkeypatch, lambda _: "business" * 100)
    agent.ctx.sandbox = object()

    async def tool(_name, _args):
        return await run()

    agent._run_tool = tool
    monkeypatch.setattr("maverick.tools.code_exec.sandbox_run",
                        lambda *a, **kw: pytest.fail("partial input must never execute"))
    result = await code_exec_tool(agent).fn({"code": "print('ok')", "tool_calls": [
        {"name": "producer"}, {"name": "producer"},
    ]})
    assert result.startswith("INDETERMINATE:") and "combined" in result
    assert len(rows) == 2 and all(row[1]["disposition"] == "completed" for row in rows)


@pytest.mark.asyncio
async def test_full_artifact_quota_degrades_to_preview_not_unknown(monkeypatch):
    """Regression: once a tenant held MAX_TENANT_FILES live artifacts, every
    later large result became INDETERMINATE for up to seven days. The tool ran;
    only retention failed -- deliver the screened preview and say so."""
    monkeypatch.setattr(artifacts, "MAX_TENANT_FILES", 0)
    agent, run, rows, _seen = agent_boundary(monkeypatch, lambda _a: "row\n" * 2000,
                                             shield=SimpleNamespace(scan_output=lambda v: SimpleNamespace(allowed=True)))
    output = await run()
    assert rows[-1][1]["disposition"] == "completed"
    assert "INDETERMINATE" not in output and "artifact_id=" not in output
    assert "Complete result NOT retained" in output and "quota" in output
