"""Offline action-group requests must match the packaged server contract."""
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick_dashboard.external_gateway import (
    _OPENAPI,
    ExternalExecuteCommitIn,
    ExternalExecuteIn,
)

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / "examples/external-agents/bedrock"


@pytest.fixture
def forwarder(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace())
    spec = importlib.util.spec_from_file_location("bedrock_contract", EXAMPLE / "forwarder/app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    monkeypatch.setattr(module, "_bearer_token", lambda **kwargs: "synthetic")
    monkeypatch.setattr(module, "_forward", lambda *args: (calls.append(args) or (200, "{}")))
    return module, calls


def event(operation, body):
    return {"operationId": operation, "parameters": [{"name": "execution_id", "value": "ex-1"}],
            "requestBody": {"content": {"application/json": {"properties": body}}}}


@pytest.mark.parametrize("operation,model", [
    ("executeAction", ExternalExecuteIn), ("commitExecution", ExternalExecuteCommitIn),
])
@pytest.mark.parametrize("encoded", [True, False])
def test_object_property_validates_through_current_server_model(forwarder, operation, model, encoded):
    module, calls = forwarder
    value = {"summary": "Synthetic task", "nested": {"items": [1, True]}}
    props = [{"name": key, "type": "string", "value": text}
             for key, text in {"connector": "fixture", "op": "create", "path": "/tasks"}.items()]
    props.append({"name": "body", "type": "object", "value": json.dumps(value) if encoded else value})
    result = module.lambda_handler(event(operation, props), None)
    assert result["response"]["httpStatusCode"] == 200
    assert model.model_validate(calls[0][2]).body == value


@pytest.mark.parametrize("value", ["{broken", "[]", "null", "42", [], None])
def test_invalid_object_returns_actionable_error_before_forwarding(forwarder, value):
    module, calls = forwarder
    result = module.lambda_handler(event("executeAction", [{"name": "body", "type": "object", "value": value}]), None)
    assert result["response"]["httpStatusCode"] == 400
    assert "body: object property" in result["response"]["responseBody"]["application/json"]["body"]
    assert not calls


def test_packaged_schema_and_every_optional_route_match_current_gateway(forwarder):
    module, _ = forwarder
    packaged = json.loads((EXAMPLE / "lightwork-external.json").read_text(encoding="utf-8"))
    assert packaged == _OPENAPI
    operations = {}
    for path, item in packaged["paths"].items():
        for method, operation in item.items():
            expected = (method.upper(), path)
            operations[operation["operationId"]] = expected
            assert module._resolve_route({"apiPath": path, "httpMethod": method}) == expected
    assert operations == module.OPERATIONS


def test_optional_read_route_preserves_path_and_query_parameters(forwarder):
    module, calls = forwarder
    result = module.lambda_handler({"apiPath": "/api/v1/external/red-team/{campaign_id}/cases", "httpMethod": "GET", "parameters": [
        {"name": "campaign_id", "value": "campaign-1"},
        {"name": "runner_instance_id", "value": "runner/one"},
        {"name": "limit", "value": "2"},
    ]}, None)
    assert result["response"]["httpStatusCode"] == 200
    assert calls[0][1] == "/api/v1/external/red-team/campaign-1/cases?runner_instance_id=runner%2Fone&limit=2"


def test_existing_scalar_and_array_coercion_remains_supported(forwarder):
    module, _ = forwarder
    assert module._coerce("12", "integer") == 12
    assert module._coerce("1.25", "number") == 1.25
    assert module._coerce("true", "boolean") is True
    assert module._coerce('["a", "b"]', "array") == ["a", "b"]
