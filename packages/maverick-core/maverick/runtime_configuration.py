"""Startup configuration receipts for observed long-lived processes.

These acknowledge the configuration read during process initialization, not
provider health or successful execution. Heartbeats never replace the startup
snapshot with newly saved settings. No value or credential is published.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import secrets
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)
ROLES = {"dashboard", "worker", "channels", "grpc"}
FRESH_SECONDS = 100
_CAPTURE = None
_CAPTURE_LOCK = threading.RLock()


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def snapshot(configuration, environment=None):
    environment = dict(os.environ) if environment is None else environment
    values = {}
    def visit(value, path):
        if path:
            values[json.dumps(path)] = _digest([True, value])
        if isinstance(value, dict):
            for key, child in value.items():
                visit(child, [*path, str(key)])
    visit(configuration, [])
    env = {name: _digest(value) for name, value in environment.items()}
    return {"values": values, "environment": env, "revision": _digest([configuration, env])}


def remember(configuration, *, valid=True):
    """Capture once at the first global config read; no disk IO or recursive reads."""
    global _CAPTURE
    if _CAPTURE is not None:
        return
    with _CAPTURE_LOCK:
        if _CAPTURE is None:
            _CAPTURE = {**snapshot(configuration), "captured_at": time.time(), "valid": valid}


def enabled():
    from .config import config_source_errors, load_global_config
    cfg = load_global_config()
    section = cfg.get("settings", {})
    return (not config_source_errors(include_tenant=False)
            and isinstance(section, dict) and section.get("runtime_status", True) is True)


def _directory():
    from .config import config_path
    return config_path().parent / "runtime-configuration"


class Reporter:
    def __init__(self, role, *, directory=None, captured=None, clock=time.time):
        if role not in ROLES:
            raise ValueError("Unknown runtime consumer")
        self.role = role
        from .paths import current_tenant_id_strict
        self.global_scope = current_tenant_id_strict() is None
        self.clock = clock
        self.captured = dict(captured if captured is not None else _CAPTURE or {})
        self.directory = Path(directory) if directory is not None else _directory()
        self.identity = role + "-" + str(os.getpid()) + "-" + secrets.token_hex(8)
        self.path = self.directory / (self.identity + ".enc")
        self._stop = threading.Event()
        self._thread = None

    def renew(self):
        if not self.captured or not self.captured.get("valid"):
            return False
        from .crypto_at_rest import deployment_key_scope, seal
        from .file_lock import atomic_write_bytes, ensure_private_directory
        ensure_private_directory(self.directory)
        record = {"schema": 1, "role": self.role, "instance": self.identity, "pid": os.getpid(),
                  "seen_at": self.clock(), "global_scope": self.global_scope, **self.captured}
        with deployment_key_scope():
            atomic_write_bytes(self.path, seal(json.dumps(record).encode()), mode=0o600)
        return True

    def start(self):
        if not self.renew():
            return None
        def heartbeat():
            while not self._stop.wait(30):
                try:
                    if not enabled():
                        self.path.unlink(missing_ok=True)
                        return
                    self.renew()
                except Exception:
                    log.warning("Runtime configuration acknowledgement unavailable")
        self._thread = threading.Thread(target=heartbeat, name="configuration-receipt", daemon=True)
        self._thread.start()
        # Bound old metadata retention. These files are owned startup receipts,
        # never user content; only this fixed directory and suffix are visited.
        for path in list(self.directory.glob("*.enc"))[:1000]:
            try:
                if path.stat().st_mtime < self.clock() - 7 * 86400:
                    path.unlink()
            except OSError:
                pass
        return self

    def close(self):
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass


def start(role):
    """Best-effort receipt after native startup; observation failure is not activation."""
    try:
        if not enabled():
            return None
        return Reporter(role).start()
    except Exception:
        log.warning("Runtime configuration acknowledgement unavailable")
        return None


def records(*, directory=None, now=None):
    from .crypto_at_rest import deployment_key_scope, unseal
    folder = Path(directory) if directory is not None else _directory()
    now = time.time() if now is None else now
    found, unavailable = [], False
    try:
        paths = list(folder.glob("*.enc"))
    except OSError:
        return [], True
    if len(paths) > 1000:
        return [], True
    for path in paths:
        try:
            if path.stat().st_size > 4_000_000:
                raise ValueError("receipt exceeds limit")
            with deployment_key_scope():
                record = json.loads(unseal(path.read_bytes()))
            if (not isinstance(record, dict) or record.get("schema") != 1 or record.get("role") not in ROLES
                    or not isinstance(record.get("values"), dict) or not isinstance(record.get("environment"), dict)
                    or not isinstance(record.get("revision"), str) or type(record.get("seen_at")) not in (int, float)
                    or not re.fullmatch(r"[a-f0-9]{64}", record["revision"])
                    or not isinstance(record.get("instance"), str)
                    or type(record.get("captured_at")) not in (int, float)
                    or not math.isfinite(record["seen_at"]) or not math.isfinite(record["captured_at"])
                    or record.get("valid") is not True):
                raise ValueError("invalid receipt")
            record["fresh"] = 0 <= now - record["seen_at"] < FRESH_SECONDS
            found.append(record)
        except Exception:
            unavailable = True
    return found, unavailable


def matches(record, desired, path, environment=()):
    key = json.dumps(list(path))
    absent = _digest([False, None])
    if record["values"].get(key, absent) != desired["values"].get(key, absent):
        return False
    empty_env = _digest("")
    return all(record["environment"].get(name, empty_env) == desired["environment"].get(name, empty_env)
               for name in environment)


def setting_status(setting, desired, observed, *, unavailable=False):
    if setting.reader.startswith("maverick.server"):
        roles = {"channels"}
    elif setting.reader.startswith("maverick.grpc"):
        roles = {"grpc"}
    elif setting.reader.startswith("maverick_dashboard") or setting.path[0] == "dashboard":
        roles = {"dashboard"}
    else:
        roles = {record["role"] for record in observed} or ROLES
    relevant = [record for record in observed if record["role"] in roles]
    current = [record for record in relevant if record["fresh"] and record.get("global_scope") is True]
    receipt = [{"consumer": record["role"], "instance": record["instance"], "started_at": record["captured_at"],
                "checked_at": record["seen_at"], "startup_revision": record["revision"],
                "matches_saved": matches(record, desired, setting.path, setting.env)} for record in current]
    if unavailable:
        status, message = "unconfirmed", "Some startup receipts could not be checked. Verify the owning service."
    elif not current:
        status, message = "unconfirmed", "No current acknowledgement from the owning service. Restart or check that service."
    elif any(not row["matches_saved"] for row in receipt):
        status, message = "pending_restart", "At least one observed process started with a different value. Restart that service to apply it."
    else:
        status, message = "acknowledged", "Observed processes started with this saved value. Service health and work outcomes are checked separately."
    return {"state": status, "message": message, "processes": receipt,
            "required_consumers": sorted(roles), "stale_receipts": len(relevant) - len(current)}
