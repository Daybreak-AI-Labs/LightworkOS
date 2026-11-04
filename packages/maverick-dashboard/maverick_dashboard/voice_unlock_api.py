"""Voice unlock: each person records their voice; spoken requests are checked.

``[voice] biometric_unlock`` turns it on. People record three to five short
samples on Settings > Voice unlock (``/settings/voice-unlock``); only a voice
print made from them is kept, sealed to that person
(:mod:`maverick.voice_unlock`), and the recordings themselves are never
written anywhere. With the switch on, a spoken request (the microphone in
Chat, ``/api/v1/voice/transcribe``) from a person who recorded their voice is
turned into text only when the voice matches, at ``[voice]
unlock_threshold``. The match is a second check on top of signing in, never a
replacement for it.

The speaker model runs only when the optional ``voice-unlock`` extra is
installed and ``[voice] speaker_model_path`` names its folder; until then the
page says so plainly, recording is refused with the same reason, and the
switch can't be turned on. Enrolment, deletion and every check are recorded
in the audit log (never the audio or the voice print).
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from . import auth

log = logging.getLogger(__name__)

router = APIRouter()
API = "/api/v1/voice/unlock"
MIN_SAMPLES = 3
MAX_SAMPLES = 5
MAX_SAMPLE_BYTES = 2 * 1024 * 1024
_NO_MATCH = ("That didn't sound like your recorded voice, so the request was not used. "
             "Try again, or type it instead.")


def _person(request: Request) -> str:
    return auth.caller_principal(request) or "local administrator"


def _gate(embedder=None):
    from maverick import voice_unlock

    return voice_unlock.live_gate(embedder)


def _profiles_gate():
    """A gate for listing and deleting profiles: no model needed."""
    from maverick import voice_unlock

    return voice_unlock.VoiceGate(lambda _audio: [0.0])


def _audit(kind: str, person: str, **payload) -> None:
    from maverick.audit import audit_event

    audit_event(kind, agent="dashboard", actor=person, **payload)


def status(person: str) -> dict:
    from maverick import voice_unlock

    reason = voice_unlock.readiness()
    return {
        "ready": reason is None,
        "reason": reason or "",
        "switched_on": voice_unlock.enabled(),
        "enrolled": person in _profiles_gate().profiles(),
        "threshold": voice_unlock.unlock_threshold(),
        "min_samples": MIN_SAMPLES,
        "max_samples": MAX_SAMPLES,
    }


async def _read(upload: UploadFile) -> bytes:
    data = await upload.read(MAX_SAMPLE_BYTES + 1)
    if not data:
        raise HTTPException(status_code=400, detail="One of the recordings is empty.")
    if len(data) > MAX_SAMPLE_BYTES:
        raise HTTPException(status_code=400,
                            detail="Each recording must be under 2 MB (about a minute).")
    return data


def _refuse_unready() -> None:
    from maverick import voice_unlock

    reason = voice_unlock.readiness()
    if reason:
        raise HTTPException(status_code=409, detail=reason)


def check_spoken_request(request: Request, audio: bytes) -> str | None:
    """The unlock check on a spoken request: None to go ahead, else the plain
    reason it was refused. Only people who recorded their voice are checked,
    and only while the switch is on."""
    from maverick import voice_unlock

    if not voice_unlock.enabled():
        return None
    person = _person(request)
    if person not in _profiles_gate().profiles():
        return None
    reason = voice_unlock.readiness()
    if reason:
        return "Voice unlock is on but can't check voices right now. " + reason
    try:
        decision = _gate().decide(person, audio)
    except ValueError:
        decision = voice_unlock.GateDecision(False, 0.0, "unreadable recording")
    except Exception:  # noqa: BLE001 -- a check that can't run refuses, never waves through
        log.exception("voice unlock check failed")
        return "Voice unlock couldn't check this recording. Try again, or type your request."
    from maverick.audit import EventKind

    _audit(EventKind.VOICE_UNLOCK_CHECKED, person, surface="spoken_request",
           matched=decision.companion_ok, score=decision.score,
           threshold=voice_unlock.unlock_threshold())
    return None if decision.companion_ok else _NO_MATCH


# ------------------------------------------------------------------ page
@router.get("/settings/voice-unlock", response_class=HTMLResponse)
def voice_unlock_page(request: Request) -> HTMLResponse:
    auth.require_permission(request, "operate")
    from .app import templates

    state = status(_person(request))
    return templates.TemplateResponse(request, "voice_unlock.html", {"unlock": state})


# ------------------------------------------------------------------ API
@router.get(API)
def voice_unlock_status(request: Request) -> JSONResponse:
    auth.require_permission(request, "operate")
    return JSONResponse(status(_person(request)), headers={"Cache-Control": "no-store"})


@router.post(API + "/enrol")
async def voice_unlock_enrol(request: Request,
                             files: list[UploadFile] = File(...)) -> JSONResponse:
    """Record the signed-in person's voice from 3 to 5 WAV samples."""
    auth.require_permission(request, "operate")
    _refuse_unready()
    if not MIN_SAMPLES <= len(files) <= MAX_SAMPLES:
        raise HTTPException(status_code=400,
                            detail=f"Send {MIN_SAMPLES} to {MAX_SAMPLES} recordings.")
    samples = [await _read(upload) for upload in files]
    person = _person(request)
    from maverick import voice_unlock
    from maverick.audit import EventKind

    try:
        await run_in_threadpool(_gate().enroll, person, samples)
    except voice_unlock.VoiceUnlockUnavailable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,
                            detail="Send each recording as a WAV file of a few seconds.") from exc
    _audit(EventKind.VOICE_PROFILE_ENROLLED, person, samples=len(samples))
    return JSONResponse({"message": "Your voice is saved. The recordings were not kept.",
                         **status(person)})


@router.post(API + "/check")
async def voice_unlock_check(request: Request,
                             file: UploadFile = File(...)) -> JSONResponse:
    """Check one recording against the signed-in person's voice."""
    auth.require_permission(request, "operate")
    from maverick import voice_unlock
    from maverick.audit import EventKind

    if not voice_unlock.enabled():
        raise HTTPException(status_code=409, detail=(
            "Voice unlock is off. An administrator can turn it on under "
            "Settings > All settings."))
    _refuse_unready()
    person = _person(request)
    if person not in _profiles_gate().profiles():
        raise HTTPException(status_code=409, detail="Record your voice first.")
    audio = await _read(file)
    try:
        decision = await run_in_threadpool(_gate().decide, person, audio)
    except ValueError as exc:
        raise HTTPException(status_code=400,
                            detail="Send the recording as a WAV file of a few seconds.") from exc
    threshold = voice_unlock.unlock_threshold()
    _audit(EventKind.VOICE_UNLOCK_CHECKED, person, surface="check",
           matched=decision.companion_ok, score=decision.score, threshold=threshold)
    return JSONResponse({
        "matched": decision.companion_ok, "score": decision.score, "threshold": threshold,
        "message": ("That's your voice." if decision.companion_ok
                    else "That didn't match your recorded voice."),
    })


@router.delete(API + "/profile")
def voice_unlock_delete(request: Request) -> JSONResponse:
    """Erase the signed-in person's voice print."""
    auth.require_permission(request, "operate")
    from maverick.audit import EventKind

    person = _person(request)
    removed = _profiles_gate().delete_profile(person)
    if removed:
        _audit(EventKind.VOICE_PROFILE_DELETED, person)
    return JSONResponse({"removed": removed, **status(person)})


__all__ = ["check_spoken_request", "router", "status"]
