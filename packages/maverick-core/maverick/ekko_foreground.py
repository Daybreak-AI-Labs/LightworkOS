"""Explicit content-free desktop observers, selected on the installed computer.

macOS reads only NSWorkspace's bundle identifier. Local Linux X11 reads only
the active window, its PID and local-machine marker, then the executable
basename of a same-user process. Unknown identities are discarded before IPC
or persistence. No titles, accessibility, screenshots, arguments or content.
X11 I/O lives in a private spawn worker so an unresponsive desktop cannot hold
the collector or its Stop/cleanup indefinitely. Wayland is not supported.
"""
from __future__ import annotations

import importlib.util
import multiprocessing
import os
import re
import socket
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path

from .work_discovery import ObservedActivity

MACOS_BUNDLE_APPS = {
    "com.google.chrome": "chrome", "com.microsoft.edgemac": "edge",
    "org.mozilla.firefox": "firefox", "com.apple.safari": "safari",
    "com.microsoft.excel": "excel", "com.microsoft.powerpoint": "powerpoint",
    "com.microsoft.word": "word", "com.apple.finder": "finder",
}
LINUX_EXECUTABLE_APPS = {
    "chrome": "chrome", "chromium": "chrome", "chromium-browser": "chrome",
    "msedge": "edge", "microsoft-edge": "edge", "firefox": "firefox",
    "firefox-bin": "firefox", "nautilus": "file_manager",
    "dolphin": "file_manager", "thunar": "file_manager",
}
_LOCAL_DISPLAY = re.compile(r"^(?:unix)?:[0-9]{1,5}(?:\.[0-9]{1,3})?$")
_READ_SECONDS = 2.0
_START_SECONDS = 5.0


class ForegroundUnavailable(RuntimeError):
    """The selected desktop can no longer be read; never include raw identity."""


def _installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def foreground_options() -> dict:
    """Describe backend capability without opening a desktop or capturing data."""
    observer = None
    if sys.platform == "win32":
        platform = "Windows"
        observer = "windows_foreground"
        message = "Record recognized apps on the Windows computer where Lightwork is installed."
    elif sys.platform == "darwin":
        platform = "Mac"
        if _installed("AppKit") and _installed("objc"):
            observer = "macos_foreground"
            message = "Record recognized apps on the Mac where Lightwork is installed."
        else:
            message = "This installation is missing its Mac recorder. Install a complete Lightwork release to use it."
    elif sys.platform.startswith("linux"):
        platform = "Linux"
        if os.environ.get("WAYLAND_DISPLAY") or os.environ.get("XDG_SESSION_TYPE", "").casefold() == "wayland":
            message = "This computer uses Wayland. Automatic app recording is not supported for this desktop."
        elif not _LOCAL_DISPLAY.fullmatch(os.environ.get("DISPLAY", "")):
            message = "Automatic app recording needs a local X11 desktop on the computer where Lightwork is installed."
        elif not _installed("Xlib"):
            message = "This installation is missing its Linux recorder. Install a complete Lightwork release to use it."
        else:
            observer = "linux_x11_foreground"
            message = "Record recognized apps on the local Linux X11 desktop where Lightwork is installed."
    else:
        platform = "This computer"
        message = "Automatic app recording is not supported on this computer."
    return {"active_app": observer is not None, "observer": observer,
            "platform": platform, "availability_message": message}


class _Transitions:
    def __init__(self, resolver: Callable[[], str | None], clock=time.monotonic):
        self._resolver, self._clock = resolver, clock
        self._last_marker: str | None = None
        self._last_transition: float | None = None

    def observe(self) -> ObservedActivity | None:
        canonical = self._resolver()
        # A private reader may return only a member of the fixed vocabulary.
        if canonical not in {*MACOS_BUNDLE_APPS.values(), *LINUX_EXECUTABLE_APPS.values()}:
            canonical = None
        marker = canonical or "__unobserved__"
        if marker == self._last_marker:
            return None
        now = float(self._clock())
        duration = max(0.0, min(86_400.0, now - self._last_transition)) if self._last_transition is not None else 0.0
        self._last_marker, self._last_transition = marker, now
        return ObservedActivity(app=canonical, action="switch", object_type="none",
                                duration_seconds=duration) if canonical else None


def _macos_foreground_app() -> str | None:
    import objc
    from AppKit import NSWorkspace

    # Dashboard workers are not AppKit's main thread; drain each sample's pool.
    try:
        with objc.autorelease_pool():
            app = NSWorkspace.sharedWorkspace().frontmostApplication()
            identifier = app.bundleIdentifier() if app is not None else None
            return MACOS_BUNDLE_APPS.get(str(identifier or "").casefold())
    except Exception as exc:  # sanitize failures at this OS-only boundary
        raise ForegroundUnavailable("Desktop access ended. Recording has stopped.") from exc


class MacOSForegroundObserver(_Transitions):
    def __init__(self, *, resolver: Callable[[], str | None] | None = None, clock=time.monotonic):
        if resolver is None:
            if sys.platform != "darwin":
                raise ForegroundUnavailable("The Mac recorder is unavailable on this computer.")
            importlib.import_module("objc")
            importlib.import_module("AppKit")
        super().__init__(resolver or _macos_foreground_app, clock)


def _x11_property(window, atom, kind, length):
    value = window.get_property(atom, kind, 0, length, delete=False)
    if value is None or value.bytes_after or value.property_type != kind:
        return None
    return value


def _x11_foreground_app(display, atoms: Mapping[str, int]) -> str | None:
    from Xlib import Xatom

    active = _x11_property(display.screen().root, atoms["active"], Xatom.WINDOW, 1)
    if active is None or active.format != 32 or len(active.value) != 1 or not active.value[0]:
        return None
    window = display.create_resource_object("window", int(active.value[0]))
    process = _x11_property(window, atoms["pid"], Xatom.CARDINAL, 1)
    machine = _x11_property(window, atoms["machine"], Xatom.STRING, 64)
    if process is None or process.format != 32 or len(process.value) != 1 or machine is None or machine.format != 8:
        return None
    try:
        hostname = bytes(machine.value).rstrip(b"\0").decode("ascii").casefold().rstrip(".")
        if hostname != socket.gethostname().casefold().rstrip("."):
            return None  # a remote application's PID must not name a local process
        pid = int(process.value[0])
        if pid <= 0:
            return None
        directory = Path("/proc") / str(pid)
        before = directory.stat()
        if before.st_uid != os.geteuid():
            return None
        basename = Path(os.readlink(directory / "exe")).name.casefold()
        after = directory.stat()
        if (before.st_ino, before.st_uid) != (after.st_ino, after.st_uid):
            return None
        return LINUX_EXECUTABLE_APPS.get(basename)
    except (OSError, UnicodeError, ValueError):
        return None


def _x11_reader(connection, display_name: str) -> None:
    """Private read-only worker. Neither raw IDs nor exception text cross IPC."""
    display = None
    try:
        from Xlib import display as xdisplay
        from Xlib.error import BadWindow

        display = xdisplay.Display(display_name)
        atoms = {"active": display.intern_atom("_NET_ACTIVE_WINDOW", only_if_exists=True),
                 "pid": display.intern_atom("_NET_WM_PID", only_if_exists=True),
                 "machine": display.intern_atom("WM_CLIENT_MACHINE", only_if_exists=True)}
        if not all(atoms.values()):
            connection.send(("unavailable", None))
            return
        connection.send(("ready", None))
        while connection.recv() == "observe":
            try:
                app = _x11_foreground_app(display, atoms)
            except BadWindow:  # closing an ordinary app between fixed reads
                app = None
            connection.send(("sample", app))
    except (EOFError, BrokenPipeError):
        pass
    except Exception:  # OS/library failures stop this isolated reader, without private diagnostics
        try:
            connection.send(("unavailable", None))
        except (EOFError, BrokenPipeError, OSError):
            pass
    finally:
        # Xlib close may itself wait on I/O; the parent also enforces cleanup.
        try:
            if display is not None:
                display.close()
        except Exception:  # parent enforces bounded process cleanup, without private diagnostics
            pass
        finally:
            connection.close()


class LinuxX11ForegroundObserver(_Transitions):
    def __init__(self, *, resolver: Callable[[], str | None] | None = None, clock=time.monotonic):
        self._connection = self._process = None
        if resolver is None:
            if foreground_options()["observer"] != "linux_x11_foreground":
                raise ForegroundUnavailable("A supported local Linux X11 desktop is unavailable.")
            context = multiprocessing.get_context("spawn")  # never fork a threaded dashboard
            self._connection, child = context.Pipe()
            self._process = context.Process(target=_x11_reader,
                args=(child, os.environ["DISPLAY"]), daemon=True, name="lightwork-ekko-x11")
            try:
                self._process.start()
                child.close()
                if self._receive(_START_SECONDS)[0] != "ready":
                    raise ForegroundUnavailable("The Linux desktop recorder could not connect.")
            except Exception:
                child.close()
                self.close()
                raise
        super().__init__(resolver or self._read, clock)

    def _receive(self, timeout=_READ_SECONDS):
        try:
            if self._connection is not None and self._connection.poll(timeout):
                message = self._connection.recv()
                if isinstance(message, tuple) and len(message) == 2:
                    return message
        except (OSError, EOFError):
            pass
        self.close()
        raise ForegroundUnavailable("The desktop stopped responding. Recording has stopped.")

    def _read(self):
        try:
            self._connection.send("observe")
        except (OSError, EOFError, AttributeError) as exc:
            self.close()
            raise ForegroundUnavailable("Desktop access ended. Recording has stopped.") from exc
        kind, app = self._receive()
        if kind != "sample":
            self.close()
            raise ForegroundUnavailable("Desktop access ended. Recording has stopped.")
        return app if app in LINUX_EXECUTABLE_APPS.values() else None

    def close(self):
        process, connection = self._process, self._connection
        self._process = self._connection = None
        if connection is not None:
            connection.close()
        if process is not None and process.pid is not None:
            process.join(0.1)
            if process.is_alive():
                process.terminate()
                process.join(0.5)
            if process.is_alive():
                process.kill()
                process.join(0.5)
            if not process.is_alive():
                process.close()
        elif process is not None:
            process.close()


def foreground_observer():
    """Construct only after the caller's explicit native recording admission."""
    kind = foreground_options()["observer"]
    if kind == "windows_foreground":
        from .ekko_daemon import WindowsForegroundObserver

        return WindowsForegroundObserver()
    if kind == "macos_foreground":
        return MacOSForegroundObserver()
    if kind == "linux_x11_foreground":
        return LinuxX11ForegroundObserver()
    raise ForegroundUnavailable(foreground_options()["availability_message"])
