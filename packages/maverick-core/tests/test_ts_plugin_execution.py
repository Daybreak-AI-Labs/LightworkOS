"""Controlled local child processes qualify framing, ownership and no replay."""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import threading
import time
from pathlib import Path

import pytest
from maverick import ts_plugin_host as host
from maverick.connector_attempts import invocation_scope
from maverick.tool_reliability import run_with_retry


@pytest.fixture(autouse=True)
def cleanup():
    yield
    host._close_all_children()
    host._CHILDREN.clear()


def _plugin(tmp_path, body, protocol=host.PROTOCOL):
    script = tmp_path / "plugin.py"
    script.write_text(
        "import sys,json,time,os,pathlib\n"
        "if '--describe' in sys.argv:\n"
        f" print(json.dumps({{'protocol': {protocol!r}, 'tools': [{{'name': 'fixture', 'description': 'test', 'inputSchema': {{}}}}]}})); sys.exit()\n"
        + body, encoding="utf-8",
    )
    return host.load_ts_plugin([sys.executable, "-I", "-u", str(script)], call_timeout=0.5)[0]


def _child(tool):
    """The native child a loaded tool owns, which the exit-time index tracks.

    ``host._CHILDREN`` is a WeakSet (it must not keep discarded registries
    alive), so it has no order; the tool's own closure names its child."""
    cells = tool.fn.__closure__ or ()
    child = next(c.cell_contents for c in cells if isinstance(c.cell_contents, host._PluginChild))
    assert child in host._CHILDREN
    return child


def _threads_for(child):
    return list(child._threads)


@pytest.mark.asyncio
async def test_post_effect_eof_executes_once_even_with_outer_retry(tmp_path, monkeypatch):
    marker = tmp_path / "effects"
    tool = _plugin(tmp_path, f"req=json.loads(sys.stdin.readline()); pathlib.Path({str(marker)!r}).open('a').write('effect\\n'); sys.exit(1)\n")
    monkeypatch.setattr("maverick.tool_reliability.is_retry_safe", lambda _: True)
    result = await run_with_retry(tool.name, lambda: asyncio.to_thread(tool.fn, {}))
    assert marker.read_text().splitlines() == ["effect"]
    assert result.attempt.outcome_unknown
    assert result.attempt.dispatch_may_have_happened
    assert "reconcile" in result


def test_versioned_metadata_and_confirmed_pre_dispatch_rejection(tmp_path):
    tool = _plugin(tmp_path,
        "for line in sys.stdin:\n"
        " req=json.loads(line)\n"
        " assert req['attempt']==1 and req['replay']=='never' and req['deadline_unix_ms']>time.time()*1000\n"
        " print(json.dumps({'id':req['id'],'attempt':1,'effect':'not_started','error':'rejected before dispatch'}),flush=True)\n")
    result = tool.fn({})
    assert not result.attempt.outcome_unknown
    assert not result.attempt.dispatch_may_have_happened
    assert not result.attempt.retryable


@pytest.mark.parametrize("body", [
    "time.sleep(60)\n",  # The writer cannot flush a large request.
    "sys.stdin.readline(); sys.stdout.buffer.write(b'x'*1100000); sys.stdout.flush(); time.sleep(60)\n",
    "sys.stdin.readline();\nwhile True: sys.stdout.write('log\\n'*10000); sys.stdout.flush()\n",
    "sys.stdin.readline();\nwhile True: sys.stderr.write('x'*10000); sys.stderr.flush()\n",
])
def test_blocked_or_unbounded_pipes_have_one_deadline_and_no_orphan_threads(tmp_path, body):
    tool = _plugin(tmp_path, body)
    started = time.monotonic()
    result = tool.fn({"text": "a" * 200_000})
    assert time.monotonic() - started < 2
    assert result.startswith("ERROR:") and result.attempt.outcome_unknown
    assert _child(tool)._lease.process is None
    assert not [thread for thread in threading.enumerate() if thread.name.startswith("owned-child-")]


def test_queue_deadline_cannot_kill_another_active_request(tmp_path):
    tool = _plugin(tmp_path,
        "for line in sys.stdin:\n"
        " req=json.loads(line); time.sleep(.3)\n"
        " print(json.dumps({'id':req['id'],'attempt':1,'effect':'completed','result':'ok'}),flush=True)\n")
    child = _child(tool)
    results = []
    first = threading.Thread(target=lambda: results.append(tool.fn({})))
    first.start()
    deadline = time.monotonic() + 3
    while child._lease.process is None:
        assert time.monotonic() < deadline
        time.sleep(.005)
    child.call_timeout = .05
    second = tool.fn({})
    first.join(3)
    assert "queue timed out" in second
    assert not second.attempt.dispatch_may_have_happened
    assert results == ["ok"]


def test_success_reuses_single_bounded_reader_and_pre_dispatch_restart(tmp_path):
    tool = _plugin(tmp_path,
        "for line in sys.stdin:\n"
        " req=json.loads(line); print(json.dumps({'id':req['id'],'attempt':1,'effect':'completed','result':'ok'}),flush=True)\n")
    assert tool.fn({}) == "ok"
    child = _child(tool)
    first_process = child._lease.process
    threads = _threads_for(first_process)
    for _ in range(20):
        assert tool.fn({}) == "ok"
    assert child._lease.process is first_process and _threads_for(first_process) == threads
    first_process.proc.kill()
    first_process.proc.wait(timeout=5)
    assert tool.fn({}) == "ok"  # No bytes of this new request were dispatched to the dead child.
    assert child._lease.process is not first_process
    assert all(not thread.is_alive() for thread in threads)


@pytest.mark.asyncio
async def test_cancelled_invocation_owns_child_and_preserves_control_exception(tmp_path):
    tool = _plugin(tmp_path, "sys.stdin.readline(); time.sleep(60)\n")
    with invocation_scope() as invocation:
        task = asyncio.create_task(asyncio.to_thread(tool.fn, {}))
        while _child(tool)._lease.process is None:
            await asyncio.sleep(.005)
        proc = _child(tool)._lease.process
        invocation.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert proc.proc.poll() is not None
    assert all(not thread.is_alive() for thread in proc._threads)


def test_invalid_version_and_oversized_manifest_refused(tmp_path):
    with pytest.raises(host.TsPluginError, match="unsupported"):
        _plugin(tmp_path, "", protocol="maverick-plugin/99")
    script = tmp_path / "huge.py"
    script.write_text("print('x'*1100000)")
    with pytest.raises(host.TsPluginError, match="ProcessOutputLimit"):
        host.load_ts_plugin([sys.executable, str(script)])


def test_invalid_response_metadata_is_not_success(tmp_path):
    tool = _plugin(tmp_path,
        "req=json.loads(sys.stdin.readline()); print(json.dumps({'id':req['id'],'attempt':2,'effect':'completed','result':'ok'}),flush=True)\n")
    result = tool.fn({})
    assert "invalid execution metadata" in result
    assert result.attempt.outcome_unknown


def test_oversized_request_never_starts_child(tmp_path):
    tool = _plugin(tmp_path, "time.sleep(60)\n")
    result = tool.fn({"text": "x" * host.MAX_FRAME_BYTES})
    assert "request frame too large" in result
    assert not result.attempt.dispatch_may_have_happened
    assert _child(tool)._lease.process is None


def test_pinning_still_blocks_replacement_after_describe(tmp_path):
    tool = _plugin(tmp_path, "time.sleep(60)\n")
    script = Path(_child(tool).command[-1])
    script.write_text("raise SystemExit()")
    result = tool.fn({})
    assert "changed after manifest discovery" in result
    assert not result.attempt.dispatch_may_have_happened


@pytest.mark.skipif(not os.environ.get("MAVERICK_TEST_PLUGIN_SDK_BUILD"), reason="requires explicitly built local SDK fixture")
@pytest.mark.parametrize("crash", [False, True])
def test_actual_typescript_sdk_host_interoperation(tmp_path, crash):
    node = shutil.which("node")
    assert node, "Node is required for the explicitly enabled SDK qualification"
    build = Path(os.environ["MAVERICK_TEST_PLUGIN_SDK_BUILD"]).resolve()
    assert (build / "index.js").is_file()
    marker = tmp_path / "effects"
    script = tmp_path / "fixture.mjs"
    script.write_text(
        f"import {{defineTool,servePlugin}} from {(build / 'index.js').as_uri()!r};\n"
        "import {appendFileSync} from 'node:fs';\n"
        "await servePlugin([defineTool({name:'fixture',description:'fixture',inputSchema:{},handler:(_args,ctx)=>{\n"
        f"appendFileSync({str(marker)!r},'effect\\n');\n"
        + ("process.exit(1);\n" if crash else "return `${ctx.attempt}:${ctx.replay}`;\n")
        + "}})]);\n", encoding="utf-8",
    )
    tool = host.load_ts_plugin([node, str(script)])[0]
    result = tool.fn({})
    assert marker.read_text().splitlines() == ["effect"]
    if crash:
        assert result.attempt.outcome_unknown
    else:
        assert result == "1:never"
        assert not result.attempt.outcome_unknown
