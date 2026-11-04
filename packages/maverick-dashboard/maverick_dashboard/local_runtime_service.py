"""Reviewed operation of the existing local Launcher; no downloads or shell."""
from __future__ import annotations

import atexit
import ctypes
import hashlib
import json
import math
import os
import queue
import re
import shutil
import socket
import stat
import threading
import time
import uuid
from pathlib import Path

import httpx
from fastapi import HTTPException
from maverick import config
from maverick.authority_effects import authority_effect_fence
from maverick.budget import Budget, BudgetExceeded
from maverick.file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)
from maverick.governed_operations import digest
from maverick.local_runtime import Launcher, LocalRuntimeError, load_local_runtime
from maverick.owned_process import OwnedProcess
from maverick.paths import current_tenant_id_strict, data_dir

from . import auth, settings_all_page

PAGE = "/settings/local-ai"
_PROGRAMS = {"vllm": "vllm", "tgi": "text-generation-launcher", "llamacpp": "llama-server"}
_LABELS = {"vllm": "vLLM", "tgi": "Text Generation Inference", "llamacpp": "llama.cpp"}
_LOCK = threading.RLock()
_INSTANCE = uuid.uuid4().hex
_managed = None
_SAFE_ENV = ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "LANG", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "CUDA_VISIBLE_DEVICES")


def authority(request, *, write=False):
    auth.require_global_permission(request, "admin")
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
    actor = auth.caller_principal(request) or "local administrator"
    tenant = current_tenant_id_strict()
    return actor, tenant, digest(["local-runtime-owner-v1", actor, tenant])


def _path():
    return data_dir("local-runtime", "operations.json", tenant=None)


def _load():
    path = _path()
    if not path.exists():
        return {"generation": 0, "active": None, "requests": {}}
    try:
        if path.stat().st_size > 128 * 1024:
            raise ValueError
        value = json.loads(atomic_read_text(path))
        if (type(value) is not dict or set(value) != {"generation", "active", "requests"}
                or type(value["generation"]) is not int or value["generation"] < 0
                or type(value["requests"]) is not dict or len(value["requests"]) > 100):
            raise ValueError
        active = value["active"]
        if active is not None:
            if (type(active) is not dict or set(active) != {"run", "instance", "pid", "endpoint", "engine", "model", "model_bytes"}
                    or not _reference(active["run"]) or not _reference(active["instance"])
                    or (active["pid"] is not None and (type(active["pid"]) is not int or not 0 < active["pid"] < 2**32))
                    or type(active["endpoint"]) is not str
                    or not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}", active["endpoint"])
                    or not 0 < int(active["endpoint"].rsplit(":", 1)[1]) <= 65535
                    or active["engine"] not in _PROGRAMS or type(active["model"]) is not str or not 0 < len(active["model"]) <= 1024
                    or type(active["model_bytes"]) is not int or active["model_bytes"] < 0):
                raise ValueError
        for key, row in value["requests"].items():
            if (not _reference(key) or type(row) is not dict
                    or set(row) != {"actor", "tenant", "action", "state", "at", "message", "binding"}
                    or any(type(row[name]) is not str or not 0 < len(row[name]) <= 1024 for name in ("actor", "message"))
                    or (row["tenant"] is not None and (type(row["tenant"]) is not str or not 0 < len(row["tenant"]) <= 128))
                    or row["action"] not in {"start", "stop", "configure"} or row["state"] not in {"unknown", "started", "stopped", "saved", "waiting", "refused"}
                    or type(row["at"]) not in {int, float} or not math.isfinite(row["at"]) or row["at"] < 0
                    or type(row["binding"]) is not str or not re.fullmatch(r"[a-f0-9]{64}", row["binding"])):
                raise ValueError
        if active is not None and active["run"] not in value["requests"]:
            raise ValueError
        return value
    except (ValueError, TypeError, OSError) as exc:
        raise HTTPException(503, "Local AI operation history cannot be verified. Another server will not be started.") from exc


def _reference(value):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{32}", value) is not None


def _save(value):
    ensure_private_directory(_path().parent)
    atomic_write_text(_path(), json.dumps(value, sort_keys=True, allow_nan=False))


def _regular(path):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
            or (not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode))):
        raise ValueError("Choose an existing model, not a linked or special file.")
    return info


def _resource(path, engine):
    path = Path(path).expanduser()
    if not path.is_absolute():
        raise ValueError("Choose an existing model file or folder on this computer. Publisher downloads are not started here.")
    if path.drive.startswith("\\\\"):
        raise ValueError("Choose a model stored on this computer instead of a network location.")
    for ancestor in path.parents:
        _regular(ancestor)
    info = _regular(path)
    manifest = []
    if engine == "llamacpp":
        if not stat.S_ISREG(info.st_mode) or path.suffix.lower() != ".gguf":
            raise ValueError("Choose a local GGUF model for llama.cpp.")
        with path.open("rb") as stream:
            if stream.read(4) != b"GGUF":
                raise ValueError("The selected file is not a recognizable GGUF model.")
        manifest.append(["model", info.st_size, info.st_mtime_ns, info.st_ctime_ns])
    else:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("Choose a complete local model folder for this program.")
        weights = False
        inspected = 0
        for folder, directories, files in os.walk(path, followlinks=False):
            relative = Path(folder).relative_to(path)
            inspected += len(directories) + len(files)
            if len(relative.parts) > 4 or inspected > 2048:
                raise ValueError("This model folder exceeds the bounded local inspection. Choose a complete, smaller model folder.")
            for name in directories:
                _regular(Path(folder) / name)
            for name in files:
                source = Path(folder) / name
                item = _regular(source)
                if source.suffix.lower() in {".py", ".bin", ".pt", ".pkl", ".pickle", ".exe", ".dll", ".so"}:
                    raise ValueError("This model includes executable or unsafe weight files. Choose a local model with safe tensor weights.")
                weights = weights or source.suffix.lower() == ".safetensors"
                manifest.append([str(source.relative_to(path)), item.st_size, item.st_mtime_ns, item.st_ctime_ns])
        if not (path / "config.json").is_file() or not weights:
            raise ValueError("The selected folder needs its model description and safe tensor weights.")
    return {"path": str(path.resolve()), "label": " ".join(path.name.split()), "identity": digest(sorted(manifest)),
            "bytes": sum(row[1] for row in manifest)}


def model_choices():
    """Bounded named resources; values stay machine-selected, never commands."""
    candidates = []
    root = data_dir("models")
    if root.is_dir():
        with os.scandir(root) as entries:
            for index, item in enumerate(entries):
                if index >= 200:
                    break
                candidates.append(Path(item.path))
    try:
        configured = Path(load_local_runtime()["model"]).expanduser()
        if configured.is_absolute():
            candidates.append(configured)
    except (ValueError, OSError):
        pass
    choices = {}
    for path in candidates:
        for engine in ("llamacpp", "vllm"):
            try:
                item = _resource(path, engine)
                choices[item["path"]] = item["label"]
                break
            except (OSError, ValueError):
                continue
    return sorted(choices.items(), key=lambda item: item[1].casefold())


def _plan():
    if config.config_source_errors(include_tenant=True):
        raise ValueError("Local AI settings could not be read. Check Settings before preparing a server.")
    cfg = load_local_runtime()
    if cfg["host"] != "127.0.0.1" or not 0 <= cfg["port"] <= 65535:
        raise ValueError("Choose this computer only as the listening address and an available listening port in Local AI settings.")
    if cfg["extra_args"] or cfg["autoscale"]:
        raise ValueError("This guided operation supports standard options and one server. Turn off automatic scaling and custom program options in Settings.")
    if cfg["kv_cache"] or cfg["kv_offload_dir"]:
        raise ValueError("Turn off saved prompt reuse before preparing this private local server. Prompt files are not managed by this control.")
    resource = _resource(cfg["model"], cfg["engine"])
    binary = shutil.which(_PROGRAMS[cfg["engine"]])
    if not binary or Path(binary).drive.startswith("\\\\") or (os.name == "nt" and Path(binary).suffix.lower() != ".exe"):
        raise ValueError("The selected model server program is not installed on this computer. No program or model was downloaded.")
    info = _regular(Path(binary))
    if not stat.S_ISREG(info.st_mode) or info.st_size > 256 * 1024 * 1024:
        raise ValueError("The installed model server program could not be verified.")
    hasher, inspected = hashlib.sha256(), 0
    inspection = Budget(max_wall_seconds=4, max_dollars=0, max_tool_calls=0)
    with Path(binary).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            inspected += len(chunk)
            if inspected > 256 * 1024 * 1024:
                raise ValueError("The installed model server program exceeds the supported inspection size.")
            hasher.update(chunk)
            try:
                inspection.check()
            except BudgetExceeded as exc:
                raise ValueError("The installed model server program could not be inspected in time. Try again after checking local storage.") from exc
    binary_hash = hasher.hexdigest()
    launcher = Launcher(cfg)
    argv, extra_env = launcher.plan()
    argv[0] = str(Path(binary).resolve())
    return {"cfg": cfg, "argv": argv, "env": extra_env, "binary": binary_hash, "resource": resource,
            "endpoint": "http://127.0.0.1:" + argv[argv.index("--port") + 1]}


def _pid_alive(pid):
    if type(pid) is not int or pid < 1:
        return None
    if os.name == "nt":
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False if ctypes.get_last_error() == 87 else None
        try:
            code = wintypes.DWORD()
            return code.value == 259 if kernel.GetExitCodeProcess(handle, ctypes.byref(code)) else None
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return None


def _runtime(active):
    if not active:
        return "stopped", "No server managed by this control is running."
    if _managed and active["run"] == _managed["run"]:
        if _managed["runner"].process is None:
            return "unknown", "The earlier start has no confirmed program. Another server will not be started."
        alive = _managed["runner"].alive(_managed["runner"].process)
        return ("running", "The managed program is running. Check its service health before use.") if alive else ("stopped", "The managed program stopped. Its service is not ready.")
    if _pid_alive(active.get("pid")) is False:
        return "stopped", "The earlier program is no longer running. Its original request outcome remains separate."
    return "unknown", "An earlier start belongs to another Lightwork session. Check its saved request; another server will not be started while that program may still be running."


def state(request):
    actor, tenant, context = authority(request)
    with _LOCK, cross_process_lock(_path(), strict=True):
        saved = _load()
        runtime, message = _runtime(saved["active"])
        if not saved["active"] and _managed and _managed["runner"].alive(_managed["runner"].process):
            runtime, message = "unknown", "Another local AI process is still owned by this app. Another server will not be started."
        blocked, plan = "", None
        try:
            plan = _plan()
        except LocalRuntimeError:
            blocked = "Local AI settings need attention. Choose a supported program and valid operating limits in All settings."
        except (ValueError, OSError) as exc:
            blocked = str(exc) if isinstance(exc, ValueError) else "The selected program or model cannot be read. Choose an available local model in Settings."
        current = settings_all_page._revision()
        try:
            configured = load_local_runtime()
        except (ValueError, OSError):
            configured = {}
        serving = saved["active"] if runtime in {"running", "unknown"} else None
        return {"context": context, "revision": digest([current, saved["generation"], saved["active"], runtime, plan]),
            "settings_revision": current, "state": runtime, "message": message, "blocked": blocked,
            "can_start": runtime == "stopped" and bool(plan and plan["cfg"]["enabled"]),
            "can_stop": bool(_managed and saved["active"] and saved["active"]["run"] == _managed["run"] and _managed["runner"].process),
            "enabled": configured.get("enabled", False), "engine_choice": configured.get("engine", "vllm"),
            "model_choice": str(Path(configured.get("model", "")).expanduser().resolve()) if configured.get("model") and Path(configured["model"]).is_absolute() else "",
            "engine": _LABELS.get(serving["engine"] if serving else configured.get("engine"), ""),
            "model": serving["model"] if serving else plan["resource"]["label"] if plan else "",
            "model_bytes": serving["model_bytes"] if serving else plan["resource"]["bytes"] if plan else 0,
            "requests": [{"id": key, "action": row["action"], "state": row["state"], "at": row["at"]}
                         for key, row in sorted(saved["requests"].items(), key=lambda pair: pair[1]["at"], reverse=True)
                         if row["actor"] == actor and row["tenant"] == tenant][:10]}


def prepare_configuration(request, *, enabled, engine, model):
    actor, tenant, context = authority(request, write=True)
    if engine not in _PROGRAMS or type(enabled) is not bool or model not in dict(model_choices()):
        raise HTTPException(409, "Choose an available local model and a supported model server program.")
    try:
        resource = _resource(model, engine)
    except (OSError, ValueError) as exc:
        raise HTTPException(409, "This model does not fit the selected program. Choose a GGUF file for llama.cpp or a complete safe-tensor folder for the other programs.") from exc
    current = state(request)
    return {"id": uuid.uuid4().hex, "action": "configure", "actor": actor, "tenant": tenant, "context": context,
            "revision": current["revision"], "settings_revision": current["settings_revision"],
            "settings": {"enabled": enabled, "engine": engine, "model": resource["path"]},
            "resource": resource["identity"],
            "summary": f"Save {_LABELS[engine]} with {resource['label']} and turn local model serving {'on' if enabled else 'off'}. This does not start or stop a server, download anything, or change which AI service handles your tasks. An already running server keeps its current model until stopped."}


def prepare(request, action):
    actor, tenant, context = authority(request, write=True)
    current = state(request)
    if action not in {"start", "stop"}:
        raise HTTPException(422, "Choose Start or Stop local AI.")
    if not current["can_" + action]:
        raise HTTPException(409, current["blocked"] or ("Turn on local model serving in Settings first." if action == "start" and not current["enabled"] else current["message"]))
    summary = ("Start one installed model server on this computer using the selected existing model. It uses memory, processor or graphics capacity and electricity until stopped. No model or program is downloaded, no AI request is sent and no hosted AI fee is charged. Readiness is checked separately." if action == "start" else
               "Stop the model server owned by this control. Requests using it may fail; saved Lightwork work is kept.")
    return {"id": uuid.uuid4().hex, "action": action, "actor": actor, "tenant": tenant,
            "context": context, "revision": current["revision"], "summary": summary}


def _port_in_use(port):
    """Whether a live service holds ``port``. Elsewhere a stopped server's
    closing connections (TIME_WAIT) would fail a plain bind, so the probe sets
    SO_REUSEADDR, which a live listener still refuses. On Windows that option
    would bind over a live listener, and a plain bind already ignores closing
    connections, so it stays unset."""
    with socket.socket() as probe:
        if os.name != "nt":
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return True
    return False


class _BeforeStartRefused(Exception):
    """The exact native plan changed before any process was created."""


class _Runner:
    def __init__(self, plan):
        self.plan, self.process = plan, None

    def spawn(self, argv, *, env=None):
        # Launcher rereads deployment overrides. Refuse any change between the
        # exact reviewed plan and the actual native dispatch.
        try:
            if [self.plan["argv"][0], *argv[1:]] != self.plan["argv"] or digest(_plan()) != digest(self.plan):
                raise ValueError
        except (ValueError, OSError) as exc:
            raise _BeforeStartRefused from exc
        environment = {name: os.environ[name] for name in _SAFE_ENV if name in os.environ}
        environment.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_DATASETS_OFFLINE="1", PYTHONNOUSERSITE="1")
        environment.update(env or {})
        argv = [self.plan["argv"][0], *argv[1:]]
        self.process = OwnedProcess(argv, env=environment, hidden=True)
        process = self.process
        def drain():
            pending = {"stdout", "stderr"}
            while pending:
                for name in tuple(pending):
                    try:
                        if getattr(process, name).get(timeout=0.05) is None:
                            pending.remove(name)
                    except queue.Empty:
                        pass
        threading.Thread(target=drain, name="local-ai-output", daemon=True).start()
        return self.process

    def alive(self, handle):
        return handle is not None and handle.proc.poll() is None

    def stop(self, handle):
        handle.close()


def receipt(request, identifier):
    actor, tenant, _context = authority(request)
    with _LOCK, cross_process_lock(_path(), strict=True):
        row = _load()["requests"].get(identifier)
        if row is None:
            return None
        if row["actor"] != actor or row["tenant"] != tenant:
            raise HTTPException(404, "This saved local AI request is not available in your current account and workspace.")
        return {"action": row["action"], "state": row["state"], "at": row["at"], "message": row["message"]}


def _configuration_body(review):
    options = review["settings"]
    try:
        if _resource(options["model"], options["engine"])["identity"] != review["resource"]:
            raise ValueError
    except (OSError, ValueError) as exc:
        raise HTTPException(409, "The selected local model changed. Refresh and review it again.") from exc
    return settings_all_page.CatalogUpdate(expected_revision=review["settings_revision"], confirm=True,
        changes=[settings_all_page.SettingChange(id="local_runtime." + key, value=value) for key, value in options.items()])


def _save_configuration(request, body):
    from . import settings_store
    with settings_store._locked(strict=True):
        response = settings_all_page._catalog_update_locked(request, body)
    result = json.loads(response.body)
    if response.status_code == 202:
        return {"state": "waiting", "message": "The settings request is waiting for the required approval. Open All settings to review it; no local server was started."}
    if response.status_code >= 400:
        return {"state": "refused", "message": result.get("message") or "The local AI settings could not be saved. Review All settings before another request."}
    return {"state": "saved", "message": "Your reviewed local AI settings were saved. No server was started or stopped. Check current effective settings before starting."}


def apply(request, review):
    global _managed
    with authority_effect_fence(), _LOCK, cross_process_lock(_path(), strict=True):
        actor, tenant, context = authority(request, write=True)
        if [review["actor"], review["tenant"], review["context"]] != [actor, tenant, context]:
            raise HTTPException(409, "Your account or workspace changed. Review local AI again.")
        saved = _load()
        previous = saved["requests"].get(review["id"])
        if previous is not None:
            if previous["actor"] != actor or previous["tenant"] != tenant or previous["binding"] != digest(review):
                raise HTTPException(409, "This saved request does not match your review.")
            return receipt(request, review["id"])
        current = state(request)
        if current["revision"] != review["revision"] or (review["action"] != "configure" and not current["can_" + review["action"]]):
            raise HTTPException(409, "Local AI settings or service state changed. Refresh and review again.")
        from .system_checks_api import _record
        try:
            _record(request, "local_ai_" + review["action"] + "_requested", operation_ref=review["id"], settings=current["settings_revision"])
        except HTTPException as exc:
            raise HTTPException(503, "This change could not be admitted into the activity record. Nothing was started or changed.") from exc
        if len(saved["requests"]) >= 100:
            completed = [key for key, row in saved["requests"].items() if row["state"] in {"started", "stopped", "saved", "waiting", "refused"}
                         and (not saved["active"] or key != saved["active"]["run"])]
            if not completed:
                raise HTTPException(409, "Earlier unresolved local AI requests must be checked before another change.")
            saved["requests"].pop(completed[0])
        row = {"actor": actor, "tenant": tenant, "action": review["action"], "state": "unknown", "at": time.time(), "binding": digest(review),
               "message": "Your exact request was recorded, but its result is not confirmed. Check current status; it will not be repeated automatically."}
        saved["requests"][review["id"]] = row
        saved["generation"] += 1
        if review["action"] == "configure":
            body = _configuration_body(review)
            _save(saved)
            try:
                row.update(_save_configuration(request, body))
            except Exception:
                _save(saved)
                return receipt(request, review["id"])
        elif review["action"] == "start":
            plan = _plan()
            port = int(plan["endpoint"].rsplit(":", 1)[1])
            if _port_in_use(port):
                raise HTTPException(409, "Another service is using this local AI address. Choose an available port; no duplicate server was started.")
            if _managed and _managed["runner"].process:
                _managed["runner"].stop(_managed["runner"].process)
            saved["active"] = {"run": review["id"], "instance": _INSTANCE, "pid": None, "endpoint": plan["endpoint"],
                               "engine": plan["cfg"]["engine"], "model": plan["resource"]["label"], "model_bytes": plan["resource"]["bytes"]}
            _save(saved)  # retain uncertain admission before the OS effect
            runner = _Runner(plan)
            try:
                launcher = Launcher(plan["cfg"], runner=runner)
                _managed = {"run": review["id"], "runner": runner, "launcher": launcher}
                launcher.start()
                saved["active"]["pid"] = runner.process.proc.pid
                row.update(state="started", message="Your exact server start was accepted. Check service health before using the local model.")
            except (_BeforeStartRefused, LocalRuntimeError, OSError) as exc:
                if runner.process is None:
                    saved["active"] = None
                    _managed = None
                    row.update(state="refused", message=(
                        "The model server program could not be started on this computer. Nothing is running; check that it is installed and try again."
                        if isinstance(exc, OSError) else
                        "Local AI preparation changed before any server was started. Refresh and review again."))
                else:
                    saved["active"]["pid"] = runner.process.proc.pid
                    _save(saved)
                    return receipt(request, review["id"])
            except Exception:
                if runner.process is not None:
                    saved["active"]["pid"] = runner.process.proc.pid
                _save(saved)
                return receipt(request, review["id"])
        else:
            _save(saved)
            try:
                _managed["launcher"].stop()
                # A prior uncertain close can already have removed the native
                # replica handle. Still require the owned process to be reaped.
                _managed["runner"].stop(_managed["runner"].process)
                row.update(state="stopped", message="The server owned by this control was stopped. Saved Lightwork work was kept.")
                saved["active"] = None
                _managed = None
            except Exception:
                _save(saved)
                return receipt(request, review["id"])
        _save(saved)
        try:
            _record(request, "local_ai_" + review["action"] + "_completed", operation_ref=review["id"])
        except HTTPException:
            row["message"] += " The completion activity record could not be confirmed; its saved operation status is available here."
            _save(saved)
        return receipt(request, review["id"])


def health(request):
    original = authority(request)
    with _LOCK, cross_process_lock(_path(), strict=True):
        active = _load()["active"]
        runtime, _message = _runtime(active)
        endpoint = active["endpoint"] if active else None
    if not endpoint:
        return {"responding": False, "message": "No local model server has been started by this control."}
    budget = Budget(max_wall_seconds=4, max_dollars=0, max_tool_calls=0)
    try:
        with httpx.Client(timeout=2, trust_env=False, follow_redirects=False) as client:
            from maverick.governed_http import admit_client_request

            admit_client_request(client, endpoint + "/health")
            with client.stream("GET", endpoint + "/health") as response:
                responding = response.status_code == 200
        budget.check()
    except (httpx.HTTPError, TimeoutError, BudgetExceeded):
        responding = False
    if authority(request) != original:
        raise HTTPException(409, "Your account or workspace changed during the health check. Refresh local AI.")
    with _LOCK, cross_process_lock(_path(), strict=True):
        if _load()["active"] != active:
            raise HTTPException(409, "The local server changed during this health check. Refresh its current status.")
    return {"responding": responding, "message": ("The local service is responding. This does not confirm which model it loaded or the quality of its answers." if responding else
            "The local service is not responding yet. It may still be loading, or it may have stopped. Check current status before another start."),
            "server_status": {"running": "Program running", "stopped": "Server stopped", "unknown": "Status needs attention"}[runtime]}


def shutdown():
    global _managed
    with _LOCK:
        if _managed is None:
            return
        try:
            _managed["runner"].stop(_managed["runner"].process)
            with cross_process_lock(_path(), strict=True):
                saved = _load()
                if saved["active"] and saved["active"]["run"] == _managed["run"]:
                    saved["active"] = None
                    saved["generation"] += 1
                    _save(saved)
            _managed = None
        except Exception:
            pass  # uncertain retained status never permits an automatic start


atexit.register(shutdown)
