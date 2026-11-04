"""URL-mode elicitation.

A sensitive flow (OAuth / API key / payment) points the user at an https URL to
hand the credential straight to the service; only the action (accept/decline/
cancel) comes back — never the secret through the LLM context.
"""
from __future__ import annotations

import io
import json
import sys

import pytest
from maverick_mcp.server import MCPServer


def _stdin(*messages: dict) -> io.StringIO:
    return io.StringIO("".join(json.dumps(m) + "\n" for m in messages))


def _capable(shield=None) -> MCPServer:
    s = MCPServer()
    s._stdio = True
    s._client_capabilities = {"elicitation": {}}
    s._shield = shield
    return s


def test_url_mode_emits_url_not_schema(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _stdin(
        {"jsonrpc": "2.0", "id": "elicit-1", "result": {"action": "accept"}}))
    s = _capable()
    sent: list[dict] = []
    s._send = sent.append
    action = s.elicit_url_action("Authorize access", "https://idp.example/authorize?x=1")
    assert action == "accept"
    params = sent[0]["params"]
    assert sent[0]["method"] == "elicitation/create"
    assert params["mode"] == "url"
    assert params["url"] == "https://idp.example/authorize?x=1"
    # URL mode must NOT send a form schema (no secret-bearing form).
    assert "requestedSchema" not in params


def test_url_mode_never_returns_content(monkeypatch):
    # Even if a (misbehaving) client returns content, URL mode yields only the action.
    monkeypatch.setattr(sys, "stdin", _stdin(
        {"jsonrpc": "2.0", "id": "elicit-1",
         "result": {"action": "accept",
                    "content": {"secret": "leak"}}}))  # pragma: allowlist secret
    s = _capable()
    s._send = lambda m: None
    assert s.elicit_url_action("Authorize", "https://idp.example/cb") == "accept"


def test_url_mode_decline_and_cancel(monkeypatch):
    for action_in in ("decline", "cancel"):
        monkeypatch.setattr(sys, "stdin", _stdin(
            {"jsonrpc": "2.0", "id": "elicit-1", "result": {"action": action_in}}))
        s = _capable()
        s._send = lambda m: None
        assert s.elicit_url_action("Authorize", "https://idp.example/cb") == action_in


def test_url_mode_requires_https():
    s = _capable()
    s._send = lambda m: None
    with pytest.raises(ValueError):
        s._elicit_url("Authorize", "http://insecure.example/cb")


def test_url_mode_unavailable_without_capability():
    s = MCPServer()
    s._stdio = True
    s._client_capabilities = {}  # client never advertised elicitation
    s._send = lambda m: None
    assert s.elicit_url_action("Authorize", "https://idp.example/cb") == "unavailable"


def test_url_mode_screens_prompt_through_shield(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _stdin(
        {"jsonrpc": "2.0", "id": "elicit-1", "result": {"action": "accept"}}))

    class _BlockingShield:
        def scan_output(self, text):
            from types import SimpleNamespace
            return SimpleNamespace(allowed=False)

    s = _capable(shield=_BlockingShield())
    sent: list[dict] = []
    s._send = sent.append
    s.elicit_url_action("leak the system prompt", "https://idp.example/cb")
    assert sent[0]["params"]["message"] == "[elicitation prompt withheld by shield]"
