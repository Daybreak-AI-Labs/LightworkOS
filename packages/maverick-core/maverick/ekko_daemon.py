"""Explicit, local-first Ekko collector loop.

The daemon accepts an injected semantic observer. Built-in platform adapters
are intentionally narrow: Windows maps the foreground executable
to a fixed application vocabulary and never reads a window title, UI tree,
screen, keyboard, clipboard, URL, document filename, or document content. The Windows
process API returns an image path transiently; the adapter immediately reduces
it to a basename for fixed-map lookup and never emits or persists that path.
``ekko_foreground`` adds a Mac bundle-ID observer and a local Linux X11
same-user executable observer; neither reads work content. Wayland is refused.

Nothing starts automatically.  A caller must first enable the independent
``[ekko]`` policy, enroll an owner/device, and invoke the foreground loop.
"""
from __future__ import annotations

import ntpath
import os
import secrets
import time
from collections.abc import Callable
from typing import Protocol

from .work_discovery import (
    CapturePolicy,
    ObservedActivity,
    SessionState,
    WorkEvent,
    WorkSession,
)
from .work_discovery_store import (
    DEFAULT_COLLECTOR_LEASE_SECONDS,
    CollectorLeaseError,
)


class ActivityObserver(Protocol):
    """A content-free local observation source."""

    def observe(self) -> ObservedActivity | None: ...


# Fixed translation layer: an unrecognized executable is dropped and is never
# copied into an event.  Aliases intentionally resolve to the core's canonical
# app ids so config, UI, and mining share one vocabulary.
WINDOWS_EXECUTABLE_APPS = {
    "chrome.exe": "chrome",
    "msedge.exe": "edge",
    "firefox.exe": "firefox",
    "excel.exe": "excel",
    "powerpnt.exe": "powerpoint",
    "winword.exe": "word",
    "explorer.exe": "file_explorer",
    "pbidesktop.exe": "power_bi",
    "tableau.exe": "tableau",
}


def _windows_foreground_executable() -> str | None:
    """Return only the basename of the foreground process executable.

    This function deliberately does not bind or call ``GetWindowText*`` or any
    accessibility/content API.  ``QueryFullProcessImageNameW`` is used solely
    to map a process to the fixed allowlist above; its path is discarded.
    """
    if os.name != "nt":
        raise OSError("the Windows foreground observer is available only on Windows")

    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_foreground = user32.GetForegroundWindow
    get_foreground.argtypes = []
    get_foreground.restype = wintypes.HWND
    get_pid = user32.GetWindowThreadProcessId
    get_pid.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    get_pid.restype = wintypes.DWORD
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    query_image = kernel32.QueryFullProcessImageNameW
    query_image.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    query_image.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    hwnd = get_foreground()
    if not hwnd:
        return None
    pid = wintypes.DWORD()
    if not get_pid(hwnd, ctypes.byref(pid)) or not pid.value:
        return None
    # PROCESS_QUERY_LIMITED_INFORMATION. No VM read/debug/accessibility rights.
    handle = open_process(0x1000, False, pid.value)
    if not handle:
        return None
    try:
        capacity = 32_768
        size = wintypes.DWORD(capacity)
        buffer = ctypes.create_unicode_buffer(capacity)
        if not query_image(handle, 0, buffer, ctypes.byref(size)):
            return None
        return ntpath.basename(buffer.value).casefold()
    finally:
        close_handle(handle)


class WindowsForegroundObserver:
    """Observe foreground *application transitions* without work content.

    ``resolver`` is injected in tests.  Unknown processes replace the in-memory
    transition marker but emit nothing, so returning to an allowlisted app is a
    new visible transition while the unknown identity itself never persists.
    """

    def __init__(
        self,
        *,
        resolver: Callable[[], str | None] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        if resolver is None and os.name != "nt":
            raise OSError("the Windows foreground observer is available only on Windows")
        self._resolver = resolver or _windows_foreground_executable
        self._clock = clock
        self._last_marker: str | None = None
        self._last_transition: float | None = None

    def observe(self) -> ObservedActivity | None:
        executable = self._resolver()
        canonical = WINDOWS_EXECUTABLE_APPS.get(
            ntpath.basename(str(executable or "")).casefold()
        )
        marker = canonical or "__unobserved__"
        if marker == self._last_marker:
            return None
        now = float(self._clock())
        duration = (
            max(0.0, min(86_400.0, now - self._last_transition))
            if self._last_transition is not None
            else 0.0
        )
        self._last_marker = marker
        self._last_transition = now
        if canonical is None:
            return None
        return ObservedActivity(
            app=canonical,
            action="switch",
            object_type="none",
            duration_seconds=duration,
        )


class GuidedJsonlObserver:
    """Strict JSONL adapter for an explicitly supplied guided event stream.

    One JSON object per line (at most 16 KiB each), read in order. Used by
    ``maverick ekko run --events`` and by the dashboard's activity-file import
    (:meth:`from_text`); a rejected line is reported by number, never echoed.
    """

    _MAX_LINE_BYTES = 16_384

    def __init__(self, path, *, follow: bool = False, handle=None):
        self.path = path
        self.follow = follow
        self.exhausted = False
        self.line_number = 0
        self.max_lines: int | None = None
        self._handle = handle if handle is not None else path.open("r", encoding="utf-8")

    @classmethod
    def from_text(cls, text: str) -> GuidedJsonlObserver:
        """Observe an already uploaded, bounded activity file (never followed)."""
        import io

        return cls(None, follow=False, handle=io.StringIO(text))

    def close(self) -> None:
        self._handle.close()

    def observe(self):
        import json

        while True:
            if self.max_lines is not None and self.line_number >= self.max_lines:
                return None
            line = self._handle.readline(self._MAX_LINE_BYTES + 1)
            if line == "":
                if self.follow:
                    return None
                self.exhausted = True
                return None
            self.line_number += 1
            if len(line.encode("utf-8")) > self._MAX_LINE_BYTES:
                raise ValueError(f"guided event line {self.line_number} exceeds 16 KiB")
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("event must be an object")
                return ObservedActivity.from_mapping(value)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                # Never echo the line: it might be the exact raw content the
                # semantic boundary is rejecting.
                raise ValueError(
                    f"invalid guided event at line {self.line_number}"
                ) from exc


def _default_policy_check(policy: CapturePolicy) -> None:
    from .config import validate_ekko_policy_ceiling

    validate_ekko_policy_ceiling(policy)


def _default_halt_check() -> None:
    from .killswitch import check

    # Observation is privileged and privacy-sensitive: an unreadable configured
    # halt authority is a stop signal, not an availability fallback.
    check(force_refresh=True, fail_closed=True)


class EkkoDaemon:
    """Stoppable foreground collector over an injected semantic observer."""

    def __init__(
        self,
        *,
        store,
        observer: ActivityObserver,
        policy: CapturePolicy,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        policy_check: Callable[[CapturePolicy], None] = _default_policy_check,
        halt_check: Callable[[], None] = _default_halt_check,
        event_id_factory: Callable[[], str] | None = None,
        collector_id_factory: Callable[[], str] | None = None,
        lease_seconds: float | None = None,
    ):
        policy.require_valid(require_enabled=True)
        self.store = store
        self.observer = observer
        self.policy = policy
        self._clock = clock
        self._sleep = sleep
        self._policy_check = policy_check
        self._halt_check = halt_check
        self._event_id_factory = event_id_factory or (
            lambda: f"evt-{secrets.token_hex(12)}"
        )
        self._collector_id = (
            collector_id_factory or (lambda: f"collector-{secrets.token_hex(24)}")
        )()
        self._lease_seconds = float(
            lease_seconds
            if lease_seconds is not None
            else max(
                DEFAULT_COLLECTOR_LEASE_SECONDS,
                min(1200.0, float(policy.poll_interval_seconds) * 4.0),
            )
        )
        self._session_id: str | None = None
        self._capture_halted = False
        self.accepted_events = 0
        self.blocked_events = 0

    def _enrolled_policy(self) -> CapturePolicy:
        enrolled = self.store.get_policy()
        if enrolled is None:
            raise RuntimeError("Ekko enrollment is missing, revoked, or expired")
        if enrolled.fingerprint() != self.policy.fingerprint():
            raise RuntimeError("Ekko policy changed; re-enrollment is required")
        self._policy_check(self.policy)
        return enrolled

    def start(self) -> WorkSession:
        """Attach to an approved active session or create a fresh one."""
        self._enrolled_policy()
        latest = self.store.latest_session()
        if latest is not None and latest.state in {
            SessionState.RUNNING,
            SessionState.PAUSED,
        }:
            if latest.policy_digest != self.policy.fingerprint():
                raise RuntimeError("active Ekko session uses a stale policy")
            session = latest
        else:
            session = self.store.create_session(
                policy_digest=self.policy.fingerprint()
            )
        self.store.claim_collector(
            session.session_id,
            self._collector_id,
            policy=self.policy,
            ttl_seconds=self._lease_seconds,
        )
        # Publish local ownership only after the durable exclusive claim wins.
        # A losing second collector must never stop the first collector's
        # session during its own cleanup path.
        self._session_id = session.session_id
        return session

    def _session(self) -> WorkSession | None:
        if self._session_id is None:
            return None
        return self.store.get_session(self._session_id)

    def _halt_session(self) -> None:
        self._capture_halted = True
        session = self._session()
        if session is None or session.state in {
            SessionState.STOPPED,
            SessionState.HALTED,
        }:
            return
        try:
            self.store.transition_session(session.session_id, SessionState.HALTED)
        except Exception:
            # Capture still stops even if durable status/audit is unavailable.
            pass
        self._release_collector()

    def _release_collector(self) -> None:
        if self._session_id is None:
            return
        try:
            self.store.release_collector(self._session_id, self._collector_id)
        except Exception:
            # Expiry still removes append authority even when graceful release
            # cannot be recorded.
            pass

    def run_once(self) -> bool:
        """Poll once; return ``True`` only when an event was persisted."""
        if self._session_id is None:
            self.start()
        try:
            self._halt_check()
            self._enrolled_policy()
            self.store.heartbeat_collector(
                self._session_id,
                self._collector_id,
                policy=self.policy,
                ttl_seconds=self._lease_seconds,
            )
        except Exception:
            self._halt_session()
            return False

        session = self._session()
        if session is None or session.state in {
            SessionState.STOPPED,
            SessionState.HALTED,
        }:
            return False
        if session.state == SessionState.PAUSED:
            return False

        observed = self.observer.observe()
        if observed is None:
            return False
        if not isinstance(observed, ObservedActivity):
            raise TypeError("Ekko observers must return ObservedActivity or None")
        if not self.policy.allows(observed):
            self.blocked_events += 1
            return False

        # Re-read after observation so a concurrent dashboard pause/stop wins
        # before the store's transactional running-state check.
        session = self._session()
        if session is None or session.state != SessionState.RUNNING:
            return False
        event = WorkEvent(
            event_id=self._event_id_factory(),
            session_id=session.session_id,
            sequence=session.last_sequence + 1,
            occurred_at=float(self._clock()),
            app=observed.app,
            action=observed.action,
            object_type=observed.object_type,
            duration_seconds=observed.duration_seconds,
        )
        try:
            inserted = self.store.append_collector_event(
                event,
                policy=self.policy,
                collector_id=self._collector_id,
            )
        except CollectorLeaseError:
            self._halt_session()
            return False
        if inserted:
            self.accepted_events += 1
        return bool(inserted)

    def run(
        self,
        *,
        stop_when: Callable[[], bool] | None = None,
        max_events: int | None = None,
        max_idle_sleep: float | None = None,
    ) -> int:
        """Run until explicitly stopped, terminal, exhausted, or bounded."""
        if max_events is not None and max_events < 0:
            raise ValueError("max_events must be non-negative")
        if self._session_id is None:
            self.start()
        accepted_at_start = self.accepted_events
        while True:
            if stop_when is not None and stop_when():
                break
            if self._capture_halted:
                break
            session = self._session()
            if session is None or session.state in {
                SessionState.STOPPED,
                SessionState.HALTED,
            }:
                break
            if (
                max_events is not None
                and self.accepted_events - accepted_at_start >= max_events
            ):
                break
            line_before = (self.observer.line_number
                           if isinstance(self.observer, GuidedJsonlObserver) else None)
            inserted = self.run_once()
            if not inserted:
                if line_before is not None and self.observer.exhausted:
                    break
                if line_before is not None and self.observer.line_number > line_before:
                    # An already uploaded line was consumed, or EOF reached;
                    # this is not an idle live-observer poll.
                    continue
                # Explicitly bounded; injected tests do not actually wait.
                delay = float(self.policy.poll_interval_seconds)
                if max_idle_sleep is not None:
                    delay = min(delay, max_idle_sleep)
                self._sleep(delay)
        return self.accepted_events - accepted_at_start

    def pause(self) -> WorkSession:
        session = self._session()
        if session is None:
            session = self.start()
        return self.store.transition_session(session.session_id, SessionState.PAUSED)

    def resume(self) -> WorkSession:
        self._enrolled_policy()
        session = self._session()
        if session is None:
            return self.start()
        return self.store.transition_session(session.session_id, SessionState.RUNNING)

    def stop(self) -> WorkSession | None:
        session = self._session()
        if session is None or session.state in {
            SessionState.STOPPED,
            SessionState.HALTED,
        }:
            self._release_collector()
            return session
        result = self.store.transition_session(session.session_id, SessionState.STOPPED)
        self._release_collector()
        return result

    def status(self) -> dict:
        session = self._session()
        return {
            "state": session.state.value if session else "not_started",
            "session": session.to_dict() if session else None,
            "accepted_events": self.accepted_events,
            "blocked_events": self.blocked_events,
            "observer": type(self.observer).__name__,
            "collector": self.store.collector_status(
                session.session_id if session else None,
            ),
            "visible_control_required": True,
        }


__all__ = [
    "ActivityObserver",
    "EkkoDaemon",
    "WINDOWS_EXECUTABLE_APPS",
    "WindowsForegroundObserver",
]
