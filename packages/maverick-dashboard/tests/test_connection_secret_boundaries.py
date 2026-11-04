"""Real dashboard validation and Uvicorn formatting; no live provider requests."""
from __future__ import annotations

import asyncio
import copy
import io
import json
import logging
import subprocess
import sys
from unittest.mock import Mock
from urllib.parse import unquote, urlsplit

import h11
import pytest
import uvicorn
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from maverick_dashboard import app as dashboard
from starlette.requests import Request
from uvicorn.config import LOGGING_CONFIG
from uvicorn.protocols.http.flow_control import FlowControl
from uvicorn.protocols.http.h11_impl import RequestResponseCycle

CANARY = "synthetic-private-value"


@pytest.fixture
def access_log():
    """Use Uvicorn's actual config and formatter, restoring process loggers."""
    names = ("uvicorn", "uvicorn.error", "uvicorn.access")
    snapshots = {
        name: (logger.handlers[:], logger.filters[:], logger.level, logger.propagate, logger.disabled)
        for name in names if (logger := logging.getLogger(name))
    }
    output = io.StringIO()
    config = copy.deepcopy(LOGGING_CONFIG)
    config["handlers"]["access"]["stream"] = output
    config["formatters"]["access"]["use_colors"] = False
    # CLI imports the dashboard before Config reconfigures logging. This must
    # retain the boundary installed by the dashboard, not only pass in isolation.
    uvicorn.Config(dashboard.app, log_config=config)
    logger = logging.getLogger("uvicorn.access")
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    logger.addHandler(Capture())
    try:
        yield logger, output, records
    finally:
        for name, (handlers, filters, level, propagate, disabled) in snapshots.items():
            logger = logging.getLogger(name)
            logger.handlers[:] = handlers
            logger.filters[:] = filters
            logger.setLevel(level)
            logger.propagate = propagate
            logger.disabled = disabled


def send_response(access_log, raw_target):
    """Run the real HTTP protocol response/log path with an inert transport."""
    logger, output, records = access_log
    parsed = urlsplit(raw_target)
    scope = {
        "type": "http", "method": "GET", "http_version": "1.1",
        "path": unquote(parsed.path), "raw_path": parsed.path.encode("ascii"),
        "query_string": parsed.query.encode("ascii"), "headers": [],
        "client": ("127.0.0.1", 3210),
    }
    conn = h11.Connection(h11.SERVER)
    conn.receive_data(f"GET {raw_target} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode("ascii"))
    assert isinstance(conn.next_event(), h11.Request)
    transport = Mock()
    cycle = RequestResponseCycle(
        scope=scope, conn=conn, transport=transport, flow=FlowControl(transport),
        logger=logging.getLogger("uvicorn.error"), access_logger=logger,
        access_log=True, default_headers=[], message_event=asyncio.Event(),
        on_response=lambda: None,
    )
    asyncio.run(cycle.send({"type": "http.response.start", "status": 200, "headers": []}))
    return output.getvalue(), records[-1], scope


@pytest.mark.parametrize("target", [
    "/connections?code={secret}&state={secret}",
    "/connections/?%63ode={secret}&state=a&state={secret}",
    "/%63onnections?error_description={secret}&arbitrary={secret}",
    "/auth/login?return_to=%2Fconnections%3Fcode%3D{secret}%26state%3D{secret}",
    "/auth/callback?code={secret}&state={secret}",
    "/flow/approve?token={secret}",
])
def test_real_uvicorn_response_redacts_callback_before_formatters(access_log, target):
    output, record, scope = send_response(access_log, target.format(secret=CANARY))
    assert CANARY not in output
    assert CANARY not in record.getMessage()
    assert CANARY not in repr(record.args)
    assert "[redacted]" in output
    assert "200 OK" in output and "127.0.0.1:3210" in output
    # Redaction affects logging only; the callback can still consume its input.
    assert CANARY.encode() in scope["query_string"]


@pytest.mark.parametrize("target", ["/connections", "/tasks?status=open", "/connections-help?q=example"])
def test_ordinary_access_logging_is_preserved(access_log, target):
    output, record, _ = send_response(access_log, target)
    assert target in output
    assert record.args[2] == target
    assert "[redacted]" not in output


def test_direct_uvicorn_import_string_installs_redaction_after_logging_configuration():
    # Fresh interpreter proves the reverse lifecycle: Config configures its
    # handlers before importing the app via the supported Uvicorn import string.
    script = """
import logging
import uvicorn
from uvicorn.protocols.utils import get_path_with_query_string
config = uvicorn.Config('maverick_dashboard.app:app', lifespan='off')
config.load()
scope = {'path': '/connections', 'query_string': b'code=synthetic-private-value'}
logging.getLogger('uvicorn.access').info('%s - "%s %s HTTP/%s" %d',
    '127.0.0.1:3210', 'GET', get_path_with_query_string(scope), '1.1', 200)
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert CANARY not in result.stdout + result.stderr
    assert "/connections?[redacted]" in result.stdout


def test_callback_redaction_precedes_json_logging_and_root_propagation(access_log):
    from maverick.logging_config import JsonFormatter

    logger, _, _ = access_log
    root = logging.getLogger()
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    logger.propagate = True
    logging.getLogger("uvicorn").propagate = True
    try:
        send_response(access_log, f"/connections?code={CANARY}")
        assert CANARY not in output.getvalue()
        assert "/connections?[redacted]" in json.loads(output.getvalue())["msg"]
    finally:
        root.removeHandler(handler)


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, connection_oauth, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("LIGHTWORK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(connection_oauth, "_post_token", lambda *args: pytest.fail("Unexpected provider request"))
    config.reset_config_cache()
    # No lifespan or provider launch is needed to exercise the actual app handler.
    yield TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def exchange_body(**changes):
    return {"confirm": True, "context": "a" * 64, "state": "s" * 40, "code": "synthetic-code", **changes}


@pytest.mark.parametrize("changes,field", [
    ({"code": {"nested": CANARY}}, "code"),
    ({"state": CANARY}, "state"),
    ({"context": CANARY}, "context"),
    ({"confirm": CANARY}, "confirm"),
    ({CANARY: CANARY}, None),
])
def test_real_dashboard_validation_never_echoes_submitted_values(client, changes, field):
    response = client.post("/api/v1/connection-setup/exchange", json=exchange_body(**changes))
    assert response.status_code == 422, response.text
    assert CANARY not in response.text
    errors = response.json()["detail"]
    assert errors and all(set(error) == {"type", "loc", "msg"} for error in errors)
    assert errors[0]["loc"] == (["body", field] if field else ["body"])


def test_registration_secret_validation_is_field_safe(client):
    body = {"confirm": True, "context": "a" * 64, "provider": "google",
            "client_id": "synthetic-client", "client_secret": {"nested": CANARY}}
    response = client.put("/api/v1/connection-setup/application", json=body)
    assert response.status_code == 422, response.text
    assert CANARY not in response.text
    assert response.json()["detail"][0]["loc"] == ["body", "client_secret"]


def test_valid_registration_body_reaches_handler_unchanged(client, monkeypatch):
    # This positive control checks validation preservation, with explicit inert
    # authority/storage doubles; it does not qualify provider or role behavior.
    from maverick import connection_oauth
    from maverick_dashboard import connection_setup_api

    saved = []
    monkeypatch.setattr(connection_setup_api, "_authority", lambda *args, **kwargs: ("user:owner", "a" * 64))
    monkeypatch.setattr(connection_oauth, "save_workspace_application", lambda *args, **kwargs: saved.append(kwargs))
    monkeypatch.setattr(connection_setup_api, "overview", lambda *args: {"saved": True})
    response = client.put("/api/v1/connection-setup/application", json={
        "confirm": True, "context": "a" * 64, "provider": "google",
        "client_id": "synthetic-client", "client_secret": CANARY,
    })
    assert response.status_code == 200 and response.json() == {"saved": True}
    assert saved[0]["client_secret"] == CANARY
    assert CANARY not in response.text


@pytest.mark.parametrize("content,content_type", [
    (b'{"code": "synthetic-private-value", BROKEN}', "application/json"),
    (b"synthetic-private-value", "text/plain"),
    (b"\xffsynthetic-private-value", "application/octet-stream"),
])
def test_malformed_body_is_safe_and_remains_422(client, content, content_type):
    response = client.post("/api/v1/connection-setup/exchange", content=content,
                           headers={"Content-Type": content_type, "Accept": "text/html"})
    assert response.status_code == 422, response.text
    assert CANARY not in response.text
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["detail"][0]["loc"] == ["body"]


def test_validation_rebuild_drops_untrusted_messages_context_and_nested_locations():
    request = Request({"type": "http", "path": "/api/v1/connection-setup/exchange", "headers": []})
    exc = RequestValidationError([
        {"type": CANARY, "loc": ("body", "code"), "msg": CANARY,
         "input": CANARY, "ctx": {"error": ValueError(CANARY)}, "url": CANARY},
        {"type": "value_error", "loc": ("body", "code", CANARY), "msg": CANARY},
    ])
    response = asyncio.run(dashboard.validation_exception_handler(request, exc))
    assert CANARY.encode() not in response.body
    errors = json.loads(response.body)["detail"]
    assert errors[0]["loc"] == ["body", "code"]
    assert errors[1]["loc"] == ["body"]


def test_other_api_validation_contract_is_unchanged():
    request = Request({"type": "http", "path": "/api/v1/connection-setup-helper", "headers": []})
    error = {"type": "int_parsing", "loc": ["body", "count"], "msg": "Use an integer", "input": "example"}
    response = asyncio.run(dashboard.validation_exception_handler(request, RequestValidationError([error])))
    assert response.status_code == 422
    assert json.loads(response.body) == {"detail": [error]}
