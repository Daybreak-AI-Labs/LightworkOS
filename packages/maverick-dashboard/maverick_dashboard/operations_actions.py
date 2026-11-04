"""One place that mounts the action routes behind the operations pages
(Code, Immune, Audit, Oversight, Learning, Security, Research, Benchmarks,
Ekko): the buttons that replace CLI-only commands. Each module keeps its own
permission checks; this file only wires them into the app."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

from . import (
    audit_actions_api,
    benchmark_actions_api,
    code_actions_api,
    immune_actions_api,
    learning_actions_api,
    learning_holdout_setup_api,
    learning_loop_api,
    learning_ops_api,
    learning_pending_cases_api,
    learning_test_cases_api,
    privacy_notice_proposals_api,
    research_actions_api,
    training_ops_api,
    value_proof_api,
    workforce_ops_api,
)

api_router = APIRouter()
api_router.include_router(code_actions_api.router)
api_router.include_router(immune_actions_api.router)
api_router.include_router(learning_actions_api.router)
api_router.include_router(learning_loop_api.router)
api_router.include_router(audit_actions_api.router)
api_router.include_router(research_actions_api.router)
api_router.include_router(benchmark_actions_api.router)
api_router.include_router(value_proof_api.router)
api_router.include_router(learning_ops_api.router)
api_router.include_router(learning_test_cases_api.router)
api_router.include_router(learning_holdout_setup_api.router)
api_router.include_router(learning_pending_cases_api.router)
api_router.include_router(privacy_notice_proposals_api.router)
api_router.include_router(training_ops_api.router)
api_router.include_router(workforce_ops_api.router)

asset_router = APIRouter()
asset_router.include_router(code_actions_api.asset_router)
asset_router.include_router(learning_ops_api.asset_router)

# Page scripts for these pages, each on an explicit route (no directory mount).
_ASSETS = ("lightwork-security-hunt.js", "lightwork-research-plain.js")


def _asset(name: str):
    async def serve() -> FileResponse:
        return FileResponse(Path(__file__).parent / "static" / name,
                            media_type="application/javascript; charset=utf-8",
                            headers={"Cache-Control": "no-store, private, max-age=0",
                                     "X-Content-Type-Options": "nosniff"})
    serve.__name__ = "asset_" + name.replace("-", "_").replace(".", "_")
    return serve


for _name in _ASSETS:
    asset_router.add_api_route("/static/" + _name, _asset(_name), methods=["GET"],
                               include_in_schema=False)

__all__ = ["api_router", "asset_router"]
