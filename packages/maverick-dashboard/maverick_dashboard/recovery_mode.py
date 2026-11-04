"""Separate local recovery startup; no normal application lifespan executes."""
from __future__ import annotations

from contextlib import asynccontextmanager

from starlette.responses import JSONResponse, RedirectResponse


def enabled(app) -> bool:
    return getattr(app.state, "workspace_recovery_mode", False) is True


def isolated(app) -> bool:
    from maverick.control_plane_lease import current, lock_path, override_enabled
    lease = current()
    return (enabled(app) and getattr(app.state, "workspace_recovery_started", False) is True
            and lease is not None and lease is getattr(app.state, "workspace_recovery_lease", None)
            and lease.holder.role == "workspace-recovery" and lease.path == lock_path()
            and not override_enabled())


@asynccontextmanager
async def recovery_lifespan(app):
    from maverick.control_plane_lease import acquire, current, release

    from .app import _assert_dashboard_auth_configured

    # This replaces the fully composed lifespan, including scanner, discovery,
    # governance-loop and flow-trigger wrappers. None of their starts run.
    _assert_dashboard_auth_configured()
    if current() is not None:
        raise RuntimeError("Recovery cannot reuse an existing control plane; start a separate recovery process.")
    lease = acquire(role="workspace-recovery")
    if lease is None:
        raise RuntimeError("Recovery requires an enforced single control plane lock.")
    app.state.workspace_recovery_started = True
    app.state.workspace_recovery_lease = lease
    try:
        yield
    finally:
        app.state.workspace_recovery_started = False
        app.state.workspace_recovery_lease = None
        release()


def configure(app, *, host: str) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("Workspace recovery mode can bind only to loopback.")
    app.state.workspace_recovery_mode = True
    app.router.lifespan_context = recovery_lifespan


class RecoveryOnlyMiddleware:
    """Fail closed for all normal HTTP/WebSocket paths in recovery mode."""

    def __init__(self, app, *, dashboard_app):
        self.app = app
        self.dashboard_app = dashboard_app

    async def __call__(self, scope, receive, send):
        if enabled(self.dashboard_app) and scope["type"] in {"http", "websocket"}:
            path = scope.get("path", "")
            allowed = (path in {"/workspace/recovery", "/provider-spending", "/help", "/livez"}
                       or path.startswith("/api/v1/recovery/")
                       or path.startswith("/api/v1/support/") or path.startswith("/auth/")
                       or (path.startswith("/static/") and scope.get("method") in {"GET", "HEAD"}))
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            if path == "/healthz":
                # The desktop's readiness handshake needs the fixed identity;
                # answer it without the deep checks, which open the workspace.
                response = JSONResponse({"status": "recovery", "detail": "Local recovery mode is active."}, status_code=503,
                                        headers={"Cache-Control": "no-store", "X-Lightwork-Service": "dashboard-v1"})
                await response(scope, receive, send)
                return
            if path == "/" and scope.get("method") in {"GET", "HEAD"}:
                # The desktop opens "/" once that identity answers (Reconnect,
                # Open in browser); in recovery mode its home is recovery.
                response = RedirectResponse("/workspace/recovery", status_code=303, headers={"Cache-Control": "no-store"})
                await response(scope, receive, send)
                return
            if not allowed:
                response = JSONResponse({"detail": "Local recovery mode is active. Return to normal work from the desktop app after recovery."}, status_code=503,
                                        headers={"Cache-Control": "no-store"})
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
