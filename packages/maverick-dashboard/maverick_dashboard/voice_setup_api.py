"""Explicit, administrator-reviewed setup of the configured local speech model."""
from __future__ import annotations

import contextvars
import hashlib
import importlib.util
import json
import os
import threading
import uuid

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import config, voice_models
from maverick.paths import current_tenant_id
from pydantic import BaseModel, ConfigDict, Field

from .auth import _authorization_principal, constant_time_equals, require_global_permission

router = APIRouter(prefix="/api/v1/voice/setup", tags=["v1"])
_ACTIVE = frozenset({"checking", "downloading", "cancelling"})


def _target() -> dict:
    from maverick.tools.voice import _default_stt_backend

    from .voice_policy import voice_commands_enabled as _voice_commands_enabled

    cfg = voice_models._voice_cfg()
    name = voice_models.configured_model()
    pinned = voice_models.KNOWN_MODELS.get(name)
    model = None if pinned is None else {
        "id": name, "sha256": pinned[1], "size_bytes": pinned[2],
        "source_url": voice_models._BASE_URL + pinned[0],
    }
    managed = bool(os.environ.get("MAVERICK_WHISPER_CPP_MODEL") or cfg.get("whisper_cpp_model"))
    backend = _default_stt_backend()
    reason = None
    if config.config_source_errors(include_tenant=True):
        reason = "Settings could not be read. Repair the configuration before speech setup."
    elif not _voice_commands_enabled():
        reason = "Voice commands are disabled by this deployment's settings."
    elif managed:
        reason = "This deployment uses a managed speech model path. This download cannot replace or activate it."
    elif model is None:
        reason = "The configured speech model is outside the supported download catalog."
    elif backend not in {"auto", "local"}:
        reason = "A cloud speech provider is selected. Local model setup does not change that selection."
    elif not voice_models.download_egress_permitted(model["source_url"]):
        reason = "The deployment or workspace network policy blocks this model source. Setup cannot override that policy."
    return {"model": model, "enabled": _voice_commands_enabled(), "can_download": reason is None,
            "reason": reason, "configuration": {"managed_path": managed,
            "auto_fetch": voice_models.auto_fetch_enabled(), "backend": backend}}


def _target_key(target: dict) -> str:
    # No paths are returned to the browser, but a changed home or custom path
    # invalidates a previously reviewed action as well as a changed model.
    private = [str(voice_models.models_dir()), os.environ.get("MAVERICK_WHISPER_CPP_MODEL"),
               voice_models._voice_cfg().get("whisper_cpp_model"), target]
    return hashlib.sha256(json.dumps(private, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _admit(request: Request, *, mutation: bool = False) -> tuple[dict, str, str]:
    require_global_permission(request, "admin")
    target = _target()
    key = _target_key(target)
    context = hashlib.sha256(json.dumps([key, current_tenant_id(),
        _authorization_principal(request) or "local"]).encode()).hexdigest()
    supplied = request.headers.get("X-Lightwork-Voice-Context", "")
    if (mutation or supplied) and not constant_time_equals(supplied, context):
        raise HTTPException(409, "The account, workspace, or speech settings changed. Reload speech setup and review it again.")
    return target, key, context


def _engine_available() -> bool:
    from maverick.tools.voice import _find_whisper_cpp

    try:
        return importlib.util.find_spec("pywhispercpp") is not None or _find_whisper_cpp() is not None
    except (ImportError, ValueError):
        return False


class VoiceSetup:
    """One bounded in-memory job per dashboard; reload observes the same job.

    A process restart forgets progress and reports files as unverified. Only
    explicit setup may verify them; presence alone is never readiness proof.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.job: dict | None = None
        self.thread: threading.Thread | None = None
        self.cancel = threading.Event()
        self.key = ""
        self.fingerprint = None

    def view(self, key: str) -> dict | None:
        with self.lock:
            return dict(self.job) if self.key == key and self.job else None

    def start(self, target: dict, key: str) -> None:
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise HTTPException(409, "Speech setup is already running. Refresh its progress before starting another download.")
            self.key = key
            self.cancel = threading.Event()
            self.fingerprint = None
            self.job = {"id": uuid.uuid4().hex, "state": "checking", "received_bytes": 0,
                        "total_bytes": target["model"]["size_bytes"], "error": None}
            ctx = contextvars.copy_context()
            self.thread = threading.Thread(target=ctx.run, args=(self._run, target, key),
                                           name="voice-model-setup", daemon=True)
            self.thread.start()

    def _run(self, target: dict, key: str) -> None:
        def unchanged():
            if _target_key(_target()) != key:
                raise voice_models.DownloadCancelled("Speech settings changed. Reload and review setup again.")

        def progress(done, total):
            unchanged()
            with self.lock:
                if self.job["state"] != "cancelling":
                    self.job.update(state="downloading", received_bytes=done, total_bytes=total)

        try:
            unchanged()
            path = voice_models.download_model(target["model"]["id"], verify_existing=True,
                progress=progress, timeout=2.0, cancel=self.cancel, before_install=unchanged)
            # download_model returns only after digest/size verification when
            # verify_existing=True. An unrelated existing file never reaches ready.
            fingerprint = voice_models.verified_model_fingerprint(path, cancel=self.cancel)
            if fingerprint is None:
                raise ValueError("The model changed during setup verification.")
            unchanged()
            with self.lock:
                if self.cancel.is_set():
                    raise voice_models.DownloadCancelled("Speech setup was cancelled. Check any installed model before using it.")
                self.fingerprint = fingerprint
                self.job.update(state="ready", received_bytes=self.job["total_bytes"])
        except voice_models.DownloadCancelled as exc:
            with self.lock:
                self.job.update(state="cancelled", error=str(exc))
        except Exception:
            # Network/OS errors may embed proxy credentials or local paths.
            with self.lock:
                state = "cancelled" if self.cancel.is_set() else "failed"
                self.job.update(state=state, error=("Speech setup was cancelled." if state == "cancelled" else
                    "Speech setup could not verify and install the model. Check network access and free disk space, then retry. Existing model files were kept."))

    def cancel_job(self, identifier: str) -> None:
        with self.lock:
            if not self.job or self.job["id"] != identifier:
                raise HTTPException(409, "This setup step changed. Refresh its progress.")
            if self.job["state"] in _ACTIVE:
                self.job["state"] = "cancelling"
                self.cancel.set()

    def stop(self, *, timeout: float = 3.0, wait: bool = True) -> None:
        with self.lock:
            if self.job and self.job["state"] in _ACTIVE:
                self.job["state"] = "cancelling"
            self.cancel.set()
            thread = self.thread
        if thread and wait:
            thread.join(timeout=max(0.0, float(timeout)))


def _manager(request: Request) -> VoiceSetup:
    if not hasattr(request.app.state, "voice_setup"):
        request.app.state.voice_setup = VoiceSetup()
    return request.app.state.voice_setup


def _response(request: Request, target: dict, key: str, context: str, *, status_code=200):
    manager = _manager(request)
    # Snapshot job + checked-file identity together; a concurrent retry must
    # not pair the previous job's ready status with the new job's empty proof.
    with manager.lock:
        job = manager.view(key)
        state = "missing"
        if target["model"]:
            path = voice_models.model_path(target["model"]["id"])
            try:
                stat = path.stat()
                state = "present_unverified"
                fingerprint = voice_models.model_fingerprint(stat)
                if job and job["state"] == "ready" and manager.fingerprint == fingerprint:
                    state = "verified"
            except OSError:
                pass
        if job and job["state"] == "ready" and state != "verified":
            manager.fingerprint = None
            manager.job.update(state="failed", error="The previously verified model changed or was removed. Check it again before using local speech.")
            job = dict(manager.job)
    return JSONResponse({**target, "context": context, "model_state": state,
                         "engine_available": _engine_available(), "job": job}, status_code=status_code,
                        headers={"Cache-Control": "private, no-store"})


class DownloadIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: bool = Field(strict=True)
    model: str = Field(min_length=1, max_length=64)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(strict=True, gt=0, le=4_000_000_000)


class CancelIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str = Field(pattern=r"^[0-9a-f]{32}$")


@router.get("")
def status(request: Request):
    return _response(request, *_admit(request))


@router.post("/download", status_code=202)
def download(request: Request, body: DownloadIn):
    target, key, context = _admit(request, mutation=True)
    if body.confirm is not True:
        raise HTTPException(400, "Review the model source and download size, then explicitly confirm setup.")
    if not target["can_download"]:
        raise HTTPException(409, target["reason"])
    model = target["model"]
    if (body.model, body.sha256, body.size_bytes) != (model["id"], model["sha256"], model["size_bytes"]):
        raise HTTPException(409, "The reviewed model changed. Reload and review its current source and size.")
    _manager(request).start(target, key)
    return _response(request, target, key, context, status_code=202)


@router.post("/cancel")
def cancel(request: Request, body: CancelIn):
    target, key, context = _admit(request, mutation=True)
    manager = _manager(request)
    if manager.key != key:
        raise HTTPException(409, "This setup belongs to different speech settings. Refresh its progress.")
    manager.cancel_job(body.job_id)
    return _response(request, target, key, context)


_warmup_lock = threading.Lock()


def start_warmup(app) -> None:
    from maverick.tools.voice import warm_up_local_stt

    from .voice_policy import voice_commands_enabled as _voice_commands_enabled

    with _warmup_lock:
        existing = getattr(app.state, "voice_warmup_thread", None)
        if existing is not None and existing.is_alive():
            return
        app.state.voice_warmup_cancel = threading.Event()
        app.state.voice_warmup_thread = None
        if _voice_commands_enabled():
            thread = threading.Thread(target=contextvars.copy_context().run, args=(warm_up_local_stt,),
                kwargs={"cancel": app.state.voice_warmup_cancel}, name="voice-stt-warmup", daemon=True)
            app.state.voice_warmup_thread = thread
            thread.start()


def stop_setup(app, *, timeout: float = 3.0, wait: bool = True) -> None:
    import time

    deadline = time.monotonic() + max(0.0, float(timeout))
    with _warmup_lock:
        cancel = getattr(app.state, "voice_warmup_cancel", None)
        thread = getattr(app.state, "voice_warmup_thread", None)
        if cancel:
            cancel.set()
    manager = getattr(app.state, "voice_setup", None)
    if manager:
        manager.stop(wait=False)
    if not wait:
        return
    if manager:
        manager.stop(timeout=max(0.0, deadline - time.monotonic()))
    if thread:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
