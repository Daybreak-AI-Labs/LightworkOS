"""Run the same hostile stdio-server checks against a built client example.

Set MCP_BOUNDARY_COMMAND to a JSON argument array for a built Java, C#, or Rust
client, then run this file with python3 -m pytest.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


def tool_page(scenario: str, count: int) -> dict:
    expected = ["maverick_start", "maverick_status", "maverick_facts_get"]
    names = expected
    cursor = None
    if scenario == "pages":
        names = expected[:1] if count == 1 else expected[1:]
        cursor = "next" if count == 1 else None
    elif scenario == "cycle":
        cursor = "same"
    elif scenario == "endless":
        cursor = str(count)
    elif scenario == "too-many":
        names = expected + ["extra"] * 10_000
    elif scenario in ("heavy-pages", "heavy-cursors"):
        names = expected if count == 1 else ["extra"]
        cursor = str(count) if count < 18 else None
        if scenario == "heavy-cursors" and cursor is not None:
            cursor = "x" * (1024 * 1024) + cursor
    elif scenario == "controls":
        names = expected + ["unsafe\x1b]52;c;fixture\x07\x9b31m\u202e"]
    elif scenario == "write-backpressure":
        cursor = "x" * (1024 * 1024)
    result = {
        "tools": [
            {"name": name, "inputSchema": {"type": "object"}}
            for name in names
        ]
    }
    if cursor is not None:
        result["nextCursor"] = cursor
    if scenario == "heavy-pages":
        result["tools"][0]["description"] = "x" * (1024 * 1024)
    return result


def serve_changed(kind: str) -> None:
    count = 0
    call = None

    def reply(request_id, result):
        print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}), flush=True)

    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request["method"]
        if method == "initialize":
            reply(request["id"], {
                "protocolVersion": request["params"]["protocolVersion"],
                "capabilities": {name: {"listChanged": True} for name in ("tools", "resources", "prompts")},
                "serverInfo": {"name": "boundary-fixture", "version": "1"},
            })
        elif method.endswith("/list"):
            count += 1
            Path(os.environ["MCP_BOUNDARY_COUNT"]).write_text(str(count))
            if method == "tools/list":
                result = tool_page("success", count)
            elif method == "resources/list":
                result = {"resources": [{"uri": "test://fixture", "name": "entry"}]}
            else:
                result = {"prompts": [{"name": "entry"}]}
            if 1 < count < 112:
                result["nextCursor"] = "same"
            reply(request["id"], result)
            if count == 1:
                print(json.dumps({"jsonrpc": "2.0", "method": f"notifications/{kind}/list_changed"}), flush=True)
        elif method == "tools/call":
            call = request["id"]
        if count >= 112 and call is not None:
            reply(call, {"content": [{"type": "text", "text": "{}"}], "structuredContent": {"facts": {}}})
            call = None


def serve() -> None:
    scenario = os.environ["MCP_BOUNDARY_SCENARIO"]
    Path(os.environ["MCP_BOUNDARY_SERVER"]).write_text(str(os.getpid()))
    if scenario.startswith("changed-"):
        return serve_changed(scenario.removeprefix("changed-"))
    count = 0
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request["method"]
        if method == "initialize":
            if scenario == "controls":
                print("stderr\x1b]52;c;fixture\x07\x9b31m\u202e", file=sys.stderr, flush=True)
            if scenario == "large-stderr-descendants":
                child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
                Path(os.environ["MCP_BOUNDARY_DESCENDANT"]).write_text(str(child.pid))
            if scenario in ("large-stderr", "large-stderr-descendants"):
                print("x" * (64 * 1024 + 1), file=sys.stderr, flush=True)
            if scenario in ("error-controls", "initialization-cleanup"):
                print(json.dumps({"jsonrpc": "2.0", "id": request["id"],
                                  "error": {"code": -32603, "message": "unsafe\x1b]52;c;fixture\x07\x9b31m\u202e"}}), flush=True)
                continue
            result = {
                "protocolVersion": request["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "boundary-fixture", "version": "1"},
            }
        elif method == "tools/list":
            count += 1
            Path(os.environ["MCP_BOUNDARY_COUNT"]).write_text(str(count))
            if count > 110:
                return
            result = tool_page(scenario, count)
        elif method == "tools/call":
            if scenario == "silent-response":
                continue
            result = {
                "content": [{"type": "text", "text": "{}"}],
                "structuredContent": {"facts": {}},
                "isError": scenario == "tool-error",
            }
            if scenario == "invalid-facts":
                result["structuredContent"]["facts"] = []
            if scenario in ("large-message", "large-control"):
                size = 17 * 1024 * 1024 if scenario == "large-message" else 1024 * 1024
                result["content"][0]["text"] = "x" * size
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": request["id"],
                              "error": {"code": -32601, "message": "unsupported"}}), flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "method": "notifications/progress",
                          "params": {"progressToken": "unrequested", "progress": 1}}), flush=True)
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
        if scenario == "write-backpressure" and method == "tools/list":
            time.sleep(60)  # Stop consuming stdin while the client writes its cursor.
            return
    if scenario == "initialization-cleanup":
        time.sleep(30)  # Deliberately ignore stdin EOF; the client must reap us.


class ClientFixture:
    command: list[str]

    @classmethod
    def setUpClass(cls) -> None:
        command = os.environ.get("MCP_BOUNDARY_COMMAND")
        if not command:
            raise unittest.SkipTest("Set MCP_BOUNDARY_COMMAND to a built native client for stdio acceptance tests")
        cls.command = json.loads(command)

    def run_client(self, scenario: str) -> tuple[subprocess.CompletedProcess[str], int]:
        with tempfile.TemporaryDirectory(prefix="mcp-boundary-") as directory:
            root = Path(directory)
            launcher = root / "maverick"
            launcher.write_text(
                f"#!{sys.executable}\n"
                "import runpy\n"
                f"runpy.run_path({str(Path(__file__).resolve())!r}, run_name='mcp_fixture')\n"
            )
            launcher.chmod(0o700)
            counter = root / "count"
            descendant = root / "descendant"
            server_pid = root / "server"
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                   "MCP_BOUNDARY_SCENARIO": scenario, "MCP_BOUNDARY_COUNT": str(counter),
                   "MCP_BOUNDARY_DESCENDANT": str(descendant), "MCP_BOUNDARY_SERVER": str(server_pid)}
            with subprocess.Popen(self.command, env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, start_new_session=True) as process:
                try:
                    stdout, stderr = process.communicate(
                        timeout=45 if scenario.startswith(("large-", "changed-")) or scenario in ("silent-response", "write-backpressure") else 20)
                except subprocess.TimeoutExpired:
                    # The fixture owns this process group. Also clean up an
                    # orphaned server holding a pipe after the client exits.
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate(timeout=5)
                    raise
                completed = subprocess.CompletedProcess(self.command, process.returncode, stdout, stderr)
                for process_file in (server_pid, descendant):
                    if not process_file.exists():
                        continue
                    deadline = time.monotonic() + 1
                    while True:
                        try:
                            alive = Path(f"/proc/{int(process_file.read_text())}/stat").read_text().split()[2] != "Z"
                        except FileNotFoundError:
                            alive = False
                        if not alive or time.monotonic() >= deadline:
                            break
                        time.sleep(0.01)
                    if alive:
                        os.killpg(process.pid, signal.SIGKILL)
                        raise AssertionError(f"MCP client left its {process_file.name} running; stderr={stderr[:5000]!r}")
            return completed, int(counter.read_text()) if counter.exists() else 0


class StdioBoundaries(ClientFixture, unittest.TestCase):
    def test_initialization_refusal_reaps_the_child(self) -> None:
        rejected, _ = self.run_client("initialization-cleanup")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertNotIn("round-trip OK", rejected.stdout)

    def test_catalog_retention_is_bounded_across_pages(self) -> None:
        for scenario in ("heavy-pages", "heavy-cursors"):
            with self.subTest(scenario=scenario):
                rejected, count = self.run_client(scenario)
                self.assertNotEqual(rejected.returncode, 0, rejected.stdout[:500])
                self.assertLess(count, 18)

    def test_tool_error_never_reports_success(self) -> None:
        control, _ = self.run_client("success")
        self.assertEqual(control.returncode, 0, control.stderr)
        rejected, _ = self.run_client("tool-error")
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
        self.assertNotIn("round-trip OK", rejected.stdout)

    def test_facts_must_have_the_documented_object_shape(self) -> None:
        rejected, _ = self.run_client("invalid-facts")
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
        self.assertNotIn("structuredContent OK", rejected.stdout)

    def test_tool_names_cannot_write_terminal_controls(self) -> None:
        for scenario in ("controls", "error-controls"):
            with self.subTest(scenario=scenario):
                completed, _ = self.run_client(scenario)
                output = completed.stdout + completed.stderr
                for unsafe in ("\x1b", "\x07", "\x9b", "\u202e"):
                    self.assertNotIn(unsafe, output)

    def test_paginated_enumeration_completes_or_refuses_within_bounds(self) -> None:
        completed, count = self.run_client("pages")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(count, 2)
        for scenario in ("cycle", "endless", "too-many"):
            with self.subTest(scenario=scenario):
                rejected, count = self.run_client(scenario)
                self.assertNotEqual(rejected.returncode, 0, rejected.stdout[:500])
                self.assertLessEqual(count, 100)
                self.assertNotIn("round-trip OK", rejected.stdout)


class PipedStreamBounds(ClientFixture, unittest.TestCase):
    """Java and C# pipe both child streams through line-buffering SDK readers."""

    def test_oversized_stderr_terminates_server_descendants(self) -> None:
        rejected, _ = self.run_client("large-stderr-descendants")
        self.assertNotEqual(rejected.returncode, 0)

    def test_piped_streams_refuse_oversized_lines(self) -> None:
        control, _ = self.run_client("large-control")
        self.assertEqual(control.returncode, 0, control.stderr)
        for scenario in ("large-message", "large-stderr"):
            with self.subTest(scenario=scenario):
                rejected, _ = self.run_client(scenario)
                self.assertNotEqual(rejected.returncode, 0, rejected.stdout[:500])
                self.assertNotIn("round-trip OK", rejected.stdout)


class ResponseDeadline(ClientFixture, unittest.TestCase):
    def test_missing_or_discarded_reply_cannot_leave_a_request_waiting_forever(self) -> None:
        for scenario in ("large-message", "silent-response"):
            with self.subTest(scenario=scenario):
                rejected, _ = self.run_client(scenario)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertNotIn("round-trip OK", rejected.stdout)

    def test_blocked_writer_cannot_hold_cleanup_open(self) -> None:
        rejected, _ = self.run_client("write-backpressure")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertNotIn("round-trip OK", rejected.stdout)


class AutomaticRefresh(ClientFixture, unittest.TestCase):
    """The Java SDK installs automatic catalog-refresh handlers by default."""

    def test_list_change_notifications_cannot_start_unbounded_refreshes(self) -> None:
        for kind in ("tools", "resources", "prompts"):
            with self.subTest(kind=kind):
                rejected, count = self.run_client("changed-" + kind)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertLessEqual(count, 100)


if __name__ == "mcp_fixture":
    serve()
