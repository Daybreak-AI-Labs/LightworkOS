"""Static scripts for the rebuilt third-party and continuous-evidence pages.

Each dashboard script is served by an explicit route (there is no blanket
static mount); these are the page scripts added with the workflow rebuilds.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

_STATIC_DIR = Path(__file__).resolve().parent / "static"

SCRIPTS = (
    "lightwork-third-party-lifecycle.js",
    "lightwork-third-party-collaboration.js",
    "lightwork-third-party-intelligence.js",
    "lightwork-trc-continuous-evidence.js",
)

router = APIRouter(include_in_schema=False)


def _serve(name: str):
    async def script() -> FileResponse:
        return FileResponse(
            _STATIC_DIR / name,
            media_type="application/javascript; charset=utf-8",
            headers={"Cache-Control": "public, max-age=300", "X-Content-Type-Options": "nosniff"},
        )

    script.__name__ = "static_" + name.replace("-", "_").replace(".", "_")
    return script


for _name in SCRIPTS:
    router.add_api_route(f"/static/{_name}", _serve(_name), methods=["GET"])
