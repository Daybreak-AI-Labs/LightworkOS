"""Restarting this dashboard from inside it, when something will start it again.

A web app cannot start itself after it stops, so a Restart button is honest
only when the dashboard runs under something that restarts it:

* Kubernetes restarts a stopped container of a Deployment every time;
* a Linux service manager (systemd) restarts it when its service is set to
  ``Restart=on-failure`` or ``Restart=always``;
* a container engine (Docker, Podman) restarts it when the container's
  restart policy is ``on-failure``, ``always`` or ``unless-stopped``.

The restart asks the running web server to shut down gracefully (the normal
shutdown supervisor stops scheduled work and owned services) and the launcher
then exits with :data:`RESTART_EXIT_CODE`, a failure code, so every one of the
policies above starts it again. The desktop app keeps its own path (quit and
reopen, or its Reconnect menu item); a copy started by hand from a terminal
has nothing to start it again, so it gets a plain note instead of a button.
"""
from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

RESTART_EXIT_CODE = 75  # EX_TEMPFAIL: a failure, so on-failure restart policies apply
STARTED_AT = time.time()
_REQUESTED = threading.Event()

_NOTES = {
    "kubernetes": ("Kubernetes starts this app again automatically after it stops.", True),
    "systemd": ("Your server's service manager starts this app again if its service is set to restart "
                "(the usual setting). If it isn't, restart the service there.", None),
    "container": ("The container engine starts this app again if the container's restart setting allows it "
                  "(the usual setting). If it doesn't, start the container again there.", None),
    "desktop": ("The desktop app runs this copy. To restart it, quit Lightwork and open it again, or choose "
                "Reconnect Lightwork from the Lightwork menu after it stops.", False),
    "none": ("This copy was started by hand, for example from a terminal, so nothing would start it again "
             "after it stops. Restart it the same way it was started.", False),
}


def supervision(environ: Mapping[str, str] | None = None,
                exists: Callable[[str], bool] = os.path.exists) -> dict[str, Any]:
    """What would start this dashboard again: ``{"kind", "restarts", "note"}``."""
    env = os.environ if environ is None else environ
    if env.get("MAVERICK_DESKTOP_CONTROL") == "stdin-v1":
        kind = "desktop"
    elif env.get("KUBERNETES_SERVICE_HOST"):
        kind = "kubernetes"
    elif env.get("INVOCATION_ID"):
        kind = "systemd"
    elif exists("/.dockerenv") or exists("/run/.containerenv"):
        kind = "container"
    else:
        kind = "none"
    note, restarts = _NOTES[kind]
    return {"kind": kind, "restarts": restarts, "note": note}


def register_server(app: Any, server: Any) -> None:
    """Called by the launchers that own the web server object."""
    if app is None:  # a server built without an app has nothing to restart
        return
    app.state.dashboard_server = server


def status(app: Any) -> dict[str, Any]:
    info = supervision()
    server = getattr(app.state, "dashboard_server", None)
    can = server is not None and info["kind"] in {"kubernetes", "systemd", "container"}
    note = info["note"]
    if server is None and info["kind"] in {"kubernetes", "systemd", "container"}:
        note = ("This copy was started directly by its web server program rather than by Lightwork's own "
                "start command, so it can't restart itself from here. Restart it where it is run.")
    return {"label": "This app", "about": "The dashboard you are using now.", "running": True,
            "since": STARTED_AT, "can_restart": can, "note": note, "supervisor": info["kind"]}


def request(app: Any, *, delay: float = 0.5) -> None:
    """Ask the web server to stop gracefully so its supervisor starts it again."""
    server = getattr(app.state, "dashboard_server", None)
    if server is None:
        raise RuntimeError("no web server to restart")
    _REQUESTED.set()

    def stop() -> None:
        server.should_exit = True
    timer = threading.Timer(delay, stop)
    timer.daemon = True
    timer.start()


def requested() -> bool:
    return _REQUESTED.is_set()


def _reset_for_tests() -> None:
    _REQUESTED.clear()


__all__ = ["RESTART_EXIT_CODE", "STARTED_AT", "supervision", "register_server", "status", "request",
           "requested"]
