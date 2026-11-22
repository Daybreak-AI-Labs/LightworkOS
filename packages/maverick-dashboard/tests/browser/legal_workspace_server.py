"""Disposable legal journey server: real services, synthetic identity and AI boundary."""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

import server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8910)
    args = parser.parse_args()
    server.exit_cleanly_on_sigterm()
    server.CONFIG = '''[legal_workspace]
enable = true
[features]
copilot_operations = true
[copilot]
operation_families = ["tasks"]
[enterprise]
enable = false
'''
    with tempfile.TemporaryDirectory(prefix="lightwork-legal-browser-") as temporary:
        directory = Path(temporary)
        server.environment(directory)
        server.block_outbound()
        from fastapi import Request
        from fastapi.responses import JSONResponse
        from maverick import config, legal_workspace_runtime, world_model
        from maverick.llm import LLMResponse
        from maverick.oidc import VerifiedPrincipal
        from maverick_dashboard import rbac
        from maverick_dashboard.app import app

        config.reset_config_cache()
        world_model.DEFAULT_DB = directory / "world.db"
        rbac.set_role("user:browser-reviewer", "admin", actor="synthetic legal fixture")
        rbac.set_role("user:browser-colleague", "operator", actor="synthetic legal fixture")
        rbac.set_tenant_role("browser-workspace", "user:browser-colleague", "operator", actor="synthetic legal fixture")

        @app.middleware("http")
        async def synthetic_identity(request: Request, call_next):
            subject = request.headers.get("X-Browser-Principal", "browser-reviewer")
            if subject not in {"browser-reviewer", "browser-colleague"}:
                return JSONResponse({"detail": "Unknown fixture account"}, status_code=403)
            request.state.principal = VerifiedPrincipal(sub=subject, issuer="https://synthetic-legal.example.test",
                                                       audience="legal-browser-fixture", claims={"fixture": True})
            return await call_next(request)

        # Provider output is synthetic. Storage, authorization, reviews,
        # CAS, audit, UI, exports and recovery remain the native implementation.
        config.any_provider_configured = lambda: True

        def complete(_client, **kwargs):
            kwargs["dispatch_guard"]()
            packet = json.loads(kwargs["messages"][0]["content"])
            source = packet["sources"][0]
            output = {"summary": "Supplier agreement review prepared from selected evidence.",
                      "draft": "Confirm the commercial position on the liability cap with Procurement. The supplied material does not include an approved negotiation playbook.",
                      "findings": [{"claim": "The supplied agreement sets a notice date.", "source_id": source["id"], "quote": source["text"].split("\n")[0]}],
                      "questions": ["Which approved playbook applies to this supplier?"]}
            return LLMResponse(json.dumps(output), None, [], "end_turn")
        legal_workspace_runtime.LLM.complete = complete
        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=args.port, lifespan="off", log_level="warning")


if __name__ == "__main__":
    main()
