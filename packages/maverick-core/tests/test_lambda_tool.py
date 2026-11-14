"""Tests for the AWS Lambda tool (maverick.tools.lambda_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

# ---------- Lambda ----------

def _install_fake_boto3_lambda(monkeypatch, *, functions=None,
                               invoke_payload=b"{}", invoke_status=200,
                               function_cfg=None, log_events=None):
    boto3 = types.ModuleType("boto3")

    class _LambdaClient:
        meta = types.SimpleNamespace(endpoint_url="https://lambda.us-east-1.amazonaws.com")
        def list_functions(self, **k):
            return {"Functions": functions or []}

        def invoke(self, **k):
            body = MagicMock()
            body.read = lambda: invoke_payload
            return {"StatusCode": invoke_status, "Payload": body}

        def get_function(self, **k):
            return {"Configuration": function_cfg or
                    {"FunctionName": k.get("FunctionName"), "Runtime": "python3.12"}}

    class _LogsClient:
        meta = types.SimpleNamespace(endpoint_url="https://logs.us-east-1.amazonaws.com")
        def filter_log_events(self, **k):
            return {"events": log_events or []}

    def _client(service, *a, **kw):
        if service == "lambda":
            return _LambdaClient()
        if service == "logs":
            return _LogsClient()
        raise AssertionError(service)

    boto3.client = _client
    monkeypatch.setitem(sys.modules, "boto3", boto3)


def test_lambda_requires_op():
    from maverick.tools.lambda_tool import lambda_tool
    assert "op is required" in lambda_tool().fn({})


def test_lambda_missing_boto3(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)
    from maverick.tools.lambda_tool import lambda_tool
    out = lambda_tool().fn({"op": "list_functions"})
    assert "boto3 not installed" in out


def test_lambda_list_functions(monkeypatch):
    _install_fake_boto3_lambda(monkeypatch, functions=[
        {"FunctionName": "my-fn", "Runtime": "python3.12",
         "MemorySize": 512, "Timeout": 30},
    ])
    from maverick.tools.lambda_tool import lambda_tool
    out = lambda_tool().fn({"op": "list_functions"})
    assert "my-fn" in out and "python3.12" in out


def test_lambda_invoke_dry_run(monkeypatch):
    _install_fake_boto3_lambda(monkeypatch)
    from maverick.tools.lambda_tool import lambda_tool
    out = lambda_tool().fn({
        "op": "invoke", "function_name": "my-fn",
        "payload": {"x": 1}, "invocation_type": "RequestResponse",
    })
    assert "DRY RUN" in out


def test_lambda_invoke_confirmed(monkeypatch):
    _install_fake_boto3_lambda(monkeypatch, invoke_payload=b'{"ok": true}')
    from maverick.tools.lambda_tool import lambda_tool
    out = lambda_tool().fn({
        "op": "invoke", "function_name": "my-fn",
        "payload": {}, "confirm": True,
    })
    assert "status=200" in out and "ok" in out


class TestLambdaConfirmGate:
    def test_stringy_false_does_not_fire_invoke(self):
        from maverick.tools.lambda_tool import _op_invoke
        # confirm="false" is truthy as a bare string; as_bool must read it as
        # False so the live invoke is NOT fired (returns the dry-run preview).
        out = _op_invoke({"function_name": "f", "confirm": "false"})
        assert "DRY RUN" in out


def test_lambda_list_functions_handles_container_image_functions(monkeypatch):
    # Container-image functions have no Runtime; formatting None raised and
    # the whole listing failed.
    _install_fake_boto3_lambda(monkeypatch, functions=[
        {"FunctionName": "img-fn", "PackageType": "Image", "MemorySize": 512, "Timeout": 30},
    ])
    from maverick.tools.lambda_tool import lambda_tool
    out = lambda_tool().fn({"op": "list_functions"})
    assert "img-fn" in out and "runtime=Image" in out
