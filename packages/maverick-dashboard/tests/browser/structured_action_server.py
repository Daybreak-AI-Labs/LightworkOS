"""Disposable structured-action journey using native saves, approvals and execution."""
from __future__ import annotations

import argparse
import copy
import tempfile
from pathlib import Path

import server
from fastapi import HTTPException, Request


def main():
    server.exit_cleanly_on_sigterm()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server.CONFIG = server.CONFIG.replace('[security.tool_risk]', '[security.tool_risk]\nbrowser_structured_dispatch = "low"\nbrowser_protected_dispatch = "low"')
    with tempfile.TemporaryDirectory(prefix="lightwork-structured-action-") as temporary:
        directory = Path(temporary)
        server.environment(directory)
        server.block_outbound()
        app = server.build_app(directory)
        from maverick import tools
        from maverick.flow import Flow, FlowNode, store
        from maverick.paths import tenant_scope
        from maverick_dashboard.auth import caller_principal

        owner, tenant = "user:browser-reviewer", "browser-workspace"
        schema = {"type": "object", "additionalProperties": False,
            "properties": {
                "recipient": {"type": "object", "title": "Recipient details", "additionalProperties": False,
                    "properties": {"name": {"type": "string", "title": "Recipient name", "minLength": 1},
                        "priority": {"type": "boolean", "title": "Priority delivery"}}, "required": ["name", "priority"]},
                "lines": {"type": "array", "title": "Order lines", "minItems": 1, "maxItems": 4,
                    "items": {"type": "object", "additionalProperties": False,
                        "properties": {"product": {"type": "string", "title": "Product", "enum": ["standard", "premium"],
                            "enumNames": ["Standard item", "Premium item"]},
                            "quantity": {"type": "integer", "title": "Quantity", "minimum": 1},
                            "price": {"type": "number", "title": "Unit price", "minimum": 0}},
                        "required": ["product", "quantity", "price"]}},
                "notify": {"type": "boolean", "title": "Send confirmation"},
                "summary": {"type": "string", "title": "Order summary", "minLength": 1},
                "note": {"type": ["string", "null"], "title": "Delivery note", "maxLength": 200},
                "empty_details": {"type": "null", "title": "Empty details"}},
            "required": ["recipient", "lines", "notify", "summary"]}
        calls = []

        def dispatch(params):
            calls.append(copy.deepcopy(params))
            return "Recorded order for " + params["recipient"]["name"]

        original = tools.base_registry

        def registry(*args, **kwargs):
            result = original(*args, **kwargs)
            if kwargs.get("user_id") == "browser-reviewer":
                result.register(tools.Tool("browser_structured_dispatch", "Record a local synthetic order", schema, dispatch))
                result.register(tools.Tool("browser_protected_dispatch", "Synthetic protected connection action",
                    {"type": "object", "properties": {"connection_value": {"type": "string", "title": "Connection credential", "writeOnly": True},
                        "token_count": {"type": "integer", "title": "Token count"}}, "required": ["connection_value"]},
                    lambda _params: (_ for _ in ()).throw(AssertionError("A protected fixture must never execute"))))
            return result

        tools.base_registry = registry

        @app.post("/__browser_fixture/structured-action/setup", include_in_schema=False)
        def setup(request: Request):
            if caller_principal(request) != owner:
                raise HTTPException(403, "Only the synthetic owner can seed this fixture.")
            with tenant_scope(tenant=tenant):
                saved = store.save_flow(Flow(id="browser-structured-action", name="Reviewed order dispatch", owner=owner,
                    start="review", inputs=[{"key": "order_summary", "label": "Order summary", "type": "text", "required": True}], nodes={
                        "review": FlowNode(id="review", kind="approval", label="Review this order",
                            prompt="Review this saved order before recording it.", assignee=owner, next="dispatch"),
                        "dispatch": FlowNode(id="dispatch", kind="action", label="Record order",
                            tool="browser_structured_dispatch", params={}, output="receipt"),
                    }))
                store.save_flow(Flow(id="browser-protected-action", name="Existing protected action", owner=owner, start="review", nodes={
                    "review": FlowNode(id="review", kind="approval", prompt="Review protected action", next="dispatch"),
                    "dispatch": FlowNode(id="dispatch", kind="action", label="Protected connection action", tool="browser_protected_dispatch",
                        params={"connection_value": "synthetic-existing-private-value", "token_count": 12}),
                }))
                store.save_flow(Flow(id="browser-empty-action", name="Changed empty detail", owner=owner, start="dispatch", nodes={
                    "dispatch": FlowNode(id="dispatch", kind="action", label="Record order", tool="browser_structured_dispatch",
                        params={"recipient": {"name": "Alex", "priority": True}, "lines": [{"product": "premium", "quantity": 2, "price": 12.75}],
                                "notify": False, "summary": "Retained order", "empty_details": "Retained earlier value"}),
                }))
            return {"flow_id": saved.id, "synthetic": True}

        @app.get("/__browser_fixture/structured-action/state", include_in_schema=False)
        def state(request: Request):
            if caller_principal(request) != owner:
                raise HTTPException(403, "Only the synthetic owner can inspect this fixture.")
            with tenant_scope(tenant=tenant):
                flow = store.load_flow("browser-structured-action")
                return {"calls": copy.deepcopy(calls), "saved": flow.nodes["dispatch"].params}

        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning", timeout_keep_alive=server.KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
