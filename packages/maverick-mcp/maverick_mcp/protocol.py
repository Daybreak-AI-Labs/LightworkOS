"""MCP initialization negotiation and wire capability declarations."""
from __future__ import annotations

from . import __version__

PROTOCOL_VERSION = "2025-11-25"
PROTOCOL_VERSION_FALLBACK = "2024-11-05"
SUPPORTED_PROTOCOL_VERSIONS = (
    PROTOCOL_VERSION_FALLBACK, "2025-03-26", "2025-06-18", PROTOCOL_VERSION,
)
SERVER_NAME = "maverick"
SERVER_VERSION = __version__

# Transport-independent request routing. Task handlers enforce their own
# transport capability and caller authorization after dispatch.
METHOD_HANDLERS = {
    "initialize": "handle_initialize",
    "tools/list": "handle_tools_list",
    "tools/call": "handle_tools_call",
    "resources/list": "handle_resources_list",
    "resources/read": "handle_resources_read",
    "resources/subscribe": "handle_resources_subscribe",
    "resources/unsubscribe": "handle_resources_unsubscribe",
    "prompts/list": "handle_prompts_list",
    "prompts/get": "handle_prompts_get",
    "tasks/get": "handle_tasks_get",
    "tasks/result": "handle_tasks_result",
    "tasks/cancel": "handle_tasks_cancel",
    "tasks/list": "handle_tasks_list",
}


class ProtocolError(Exception):
    """JSON-RPC protocol failure that must be returned as an error envelope."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def result_envelope(request_id, result: dict) -> dict:
    """Build the same JSON-RPC result envelope for either transport."""
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_envelope(request_id, code: int, message: str) -> dict:
    """Build a JSON-RPC error without adding internal exception details."""
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": code, "message": message}}


def initialize_response(client_version: object, *, tasks_enabled: bool) -> dict:
    """Build a fresh initialize response for this transport's capabilities."""
    version = client_version if client_version in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
    capabilities = {
        "tools": {"listChanged": False},
        "resources": {"subscribe": True, "listChanged": False},
        "prompts": {"listChanged": False},
    }
    if tasks_enabled:
        capabilities["tasks"] = {
            "list": {},
            "cancel": {},
            "requests": {"tools": {"call": {}}},
        }
    return {
        "protocolVersion": version,
        "capabilities": capabilities,
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    }
