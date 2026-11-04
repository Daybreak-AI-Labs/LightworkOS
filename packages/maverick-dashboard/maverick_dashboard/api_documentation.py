"""Self-hosted API reference using FastAPI's supported Swagger UI renderer."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

router = APIRouter()
_STATIC = Path(__file__).parent / "static"
_ASSETS = {
    "swagger-ui-5.33.1-bundle.js": "application/javascript; charset=utf-8",
    "swagger-ui-5.33.1.css": "text/css; charset=utf-8",
    "swagger-ui-5.33.1-LICENSE.txt": "text/plain; charset=utf-8",
    "swagger-ui-5.33.1-NOTICE.txt": "text/plain; charset=utf-8",
    "swagger-ui-bundle.js.LICENSE.txt": "text/plain; charset=utf-8",
}


@router.get("/docs", include_in_schema=False)
def documentation(request: Request) -> HTMLResponse:
    root = request.scope.get("root_path", "").rstrip("/")
    app = request.app
    parameters = dict(app.swagger_ui_parameters or {})
    parameters.setdefault("filter", True)
    # Validate/render the current local schema without sending it to an
    # external Swagger validator. Interactive calls keep their native gates.
    parameters["validatorUrl"] = None
    redirect = app.swagger_ui_oauth2_redirect_url
    return _with_script_nonce(get_swagger_ui_html(
        openapi_url=root + "/openapi.json",
        title=app.title + " - Swagger UI",
        swagger_js_url=root + "/static/swagger-ui-5.33.1-bundle.js",
        swagger_css_url=root + "/static/swagger-ui-5.33.1.css",
        swagger_favicon_url=root + "/static/daybreak-logo.jpg",
        oauth2_redirect_url=root + redirect if redirect else None,
        init_oauth=app.swagger_ui_init_oauth,
        swagger_ui_parameters=parameters,
    ), request)


@router.get("/openapi.json", include_in_schema=False)
def openapi_schema(request: Request) -> JSONResponse:
    schema = request.app.openapi()
    root = request.scope.get("root_path", "").rstrip("/")
    if root and request.app.root_path_in_servers:
        servers = schema.get("servers", [])
        if root not in {server.get("url") for server in servers}:
            schema = {**schema, "servers": [{"url": root}, *servers]}
    return JSONResponse(schema, headers={"Cache-Control": "private, no-store"})


@router.get("/redoc", include_in_schema=False)
def redoc(request: Request) -> HTMLResponse:
    root = request.scope.get("root_path", "").rstrip("/")
    return get_redoc_html(openapi_url=root + "/openapi.json", title=request.app.title + " - ReDoc")


@router.get("/docs/oauth2-redirect", include_in_schema=False)
def oauth_redirect(request: Request) -> HTMLResponse:
    return _with_script_nonce(get_swagger_ui_oauth2_redirect_html(), request)


def _with_script_nonce(page: HTMLResponse, request: Request) -> HTMLResponse:
    """FastAPI's Swagger pages carry inline <script> blocks (the UI's own init
    code), which the nonce-based script-src blocks unless they carry this
    response's nonce. Their src= scripts are untouched."""
    nonce = getattr(request.state, "csp_script_nonce", "")
    html = bytes(page.body).decode("utf-8").replace("<script>", f'<script nonce="{nonce}">')
    return HTMLResponse(html)


def _asset(name: str, media_type: str):
    def serve() -> FileResponse:
        return FileResponse(
            _STATIC / name,
            media_type=media_type,
            headers={"Cache-Control": "private, no-store"},
        )

    serve.__name__ = "documentation_" + name.replace("-", "_").replace(".", "_")
    return serve


for _name, _media_type in _ASSETS.items():
    router.add_api_route(
        "/static/" + _name,
        _asset(_name, _media_type),
        methods=["GET"],
        include_in_schema=False,
    )
