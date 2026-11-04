"""The stdio transport preserves JSON-RPC response and notification rules."""
import logging

from maverick_mcp.protocol import METHOD_HANDLERS, ProtocolError, error_envelope, result_envelope
from maverick_mcp.stdio_transport import dispatch_stdio_message, handle_stdio_line


class _Server:
    def __init__(self):
        self._stdio_session = None
        self.messages = []

    def _send_error(self, request_id, code, message):
        self.messages.append(("error", request_id, code, message))

    def _send_result(self, request_id, result):
        self.messages.append(("result", request_id, result))

    def _flush_resource_updates(self):
        self.messages.append(("notifications",))

    def _dispatch_stdio_message(self, method, request_id, params, is_notification):
        dispatch_stdio_message(self, method, request_id, params, is_notification)

    def handle_tools_call(self, params):
        if params.get("bad"):
            raise ProtocolError(-32602, "invalid parameters")
        return {"content": [{"type": "text", "text": "done"}]}


def _handle(server, line):
    handle_stdio_line(server, line, no_id=object(), logger=logging.getLogger(__name__))


def test_null_id_is_answered_but_missing_id_is_a_notification():
    server = _Server()
    _handle(server, '{"method":"ping", "id":null}')
    _handle(server, '{"method":"ping"}')
    assert server.messages == [("result", None, {})]


def test_tool_result_precedes_resource_notifications():
    server = _Server()
    _handle(server, '{"method":"tools/call", "id":1, "params":{}}')
    assert server.messages == [
        ("result", 1, {"content": [{"type": "text", "text": "done"}]}),
        ("notifications",),
    ]


def test_invalid_tool_request_has_no_notification_or_followup():
    server = _Server()
    _handle(server, '{"method":"tools/call", "id":1, "params":{"bad":true}}')
    assert server.messages == [("error", 1, -32602, "invalid parameters")]


def test_shared_envelopes_preserve_explicit_null_id():
    assert result_envelope(None, {}) == {"jsonrpc": "2.0", "id": None, "result": {}}
    assert error_envelope(None, -32602, "invalid parameters") == {
        "jsonrpc": "2.0", "id": None,
        "error": {"code": -32602, "message": "invalid parameters"},
    }


def test_every_shared_method_routes_to_its_handler():
    for method, handler_name in METHOD_HANDLERS.items():
        server = _Server()
        setattr(server, handler_name, lambda params: params)
        dispatch_stdio_message(server, method, 7, {"method": method}, False)
        assert server.messages[0] == ("result", 7, {"method": method})
        assert server.messages[1:] == ([("notifications",)] if method == "tools/call" else [])


def test_unhashable_method_is_reported_without_crashing():
    server = _Server()
    _handle(server, '{"method":[], "id":1}')
    assert server.messages == [("error", 1, -32601, "method not found: []")]
