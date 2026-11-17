"""Replicate tool — run hosted ML models (image/video/audio gen).

Auth: ``REPLICATE_API_TOKEN``.

ops:
  - run(model, input, wait)            — create a prediction; wait polls to completion
  - predict_get(prediction_id)
  - cancel(prediction_id, confirm)
  - models(query)                      — search the model catalog

``model`` is "owner/name" or "owner/name:version". When no version is
given we resolve the latest version automatically.

Creating a prediction is a paid call charged to the run budget (kernel rule
3) through ``_paid_call.charged_call``, polling included when ``wait`` is
set: priced from ``[budget.tool_prices] replicate`` per request, per image
returned or per second of compute (``metrics.predict_time``), else the
per-call safety ceiling. A unit the reply does not report (seconds when not
waiting) is charged the ceiling. A tool built with no run budget refuses
before anything is sent.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, NamedTuple

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment
from ._paid_call import STOP_SIGNALS, charged_call

log = logging.getLogger(__name__)


_RP_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["run", "predict_get", "cancel", "models"]},
        "model": {"type": "string"},
        "input": {"type": "object"},
        "wait": {"type": "boolean", "description": "Poll until terminal (run op)."},
        "prediction_id": {"type": "string"},
        "query": {"type": "string"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_API = "https://api.replicate.com/v1"


def _token() -> str:
    t = os.environ.get("REPLICATE_API_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Replicate requires REPLICATE_API_TOKEN.")
    return t


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_token()}",
            "Content-Type": "application/json"}


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"{_API}{path}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(f"{_API}{path}", headers=_headers(), json=body, timeout=60.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _resolve_version(model: str) -> str | None:
    if ":" in model:
        return model.split(":", 1)[1]
    code, data = _get(f"/models/{model}")
    if code >= 400 or not isinstance(data, dict):
        return None
    vid = (data.get("latest_version") or {}).get("id")
    if vid:
        return vid
    # Some models don't expose latest_version on the model object;
    # fall back to the /versions list and take the most recent.
    c2, d2 = _get(f"/models/{model}/versions")
    if c2 >= 400 or not isinstance(d2, dict):
        return None
    results = d2.get("results") or []
    return results[0].get("id") if results else None


class PredictionRun(NamedTuple):
    """One prediction as :func:`run_prediction` saw it. ``final`` is its last
    state when polled to an end; ``note`` says, in plain words, that it was
    waited for to measure its cost or cancelled at its spending hold."""

    code: int
    created: Any
    final: dict | None
    poll_error: str | None
    note: str
    waited: bool


def _measured(run: PredictionRun) -> dict[str, float | None]:
    """What one prediction used, from its final state when it was polled."""
    if run.code >= 400 or not isinstance(run.created, dict):
        return {"request": 0, "image": 0, "second": 0}
    final = run.final
    if not isinstance(final, dict):
        return {}
    metrics = final.get("metrics") if isinstance(final.get("metrics"), dict) else {}
    seconds = metrics.get("predict_time")
    output = final.get("output")
    images = (len(output) if isinstance(output, list) else 0 if output is None else 1)
    return {"second": (float(seconds) if isinstance(seconds, (int, float))
                       and not isinstance(seconds, bool) else None),
            "image": images if final.get("status") == "succeeded" else 0}


def _priced_per_second() -> bool:
    from ..budget import ToolPricesUnavailable, tool_call_price

    try:
        return tool_call_price("replicate").unit == "second"
    except ToolPricesUnavailable:
        return False  # charged_call refuses the call with the reason


_CANCEL_GRACE_SECONDS = 30


def run_prediction(version: str, inp: dict, wait: bool, budget, *,
                   label: str = "Replicate") -> PredictionRun:
    """Create one prediction and, with ``wait``, poll it.

    One paid call charged to ``budget``. Priced per second, the prediction is
    always waited for, so its time can be measured, and it is cancelled once
    it has run the seconds its spending hold pays for; Replicate's reported
    seconds settle the charge, even when the cancel takes a while. Otherwise
    it is polled for up to 90 seconds and never cancelled: a longer one keeps
    running and is reported as still running.
    """
    per_second = _priced_per_second()
    waited = wait or per_second
    notes = ([f"Waited for the result to measure its cost, because {label} is priced per "
              "second."] if per_second and not wait else [])

    def follow(code, data, max_units):
        if code >= 400 or not isinstance(data, dict) or not waited:
            return PredictionRun(code, data, None, None, " ".join(notes), waited)
        pid = data.get("id")
        started = time.time()
        stop_at = started + max_units if per_second and max_units is not None else None
        end = stop_at if stop_at is not None else started + 90
        while True:
            c2, p2 = _get(f"/predictions/{pid}")
            if c2 >= 400 or not isinstance(p2, dict):
                return PredictionRun(code, data, None, f"ERROR: poll ({c2}): {p2}", " ".join(notes), waited)
            if p2.get("status") in ("succeeded", "failed", "canceled"):
                return PredictionRun(code, data, p2, None, " ".join(notes), waited)
            now = time.time()
            if now >= end:
                break
            time.sleep(min(2.0, max(0.5, end - now)))
        if stop_at is None:
            return PredictionRun(code, data, None, None, " ".join(notes), waited)
        # The spending hold is reached: stop the prediction, then read its
        # reported seconds, which settle the charge.
        _post(f"/predictions/{pid}/cancel", {})
        notes.append(f"It was cancelled at the spending hold after {round(time.time() - started)} s.")
        grace_end = time.time() + _CANCEL_GRACE_SECONDS
        while time.time() < grace_end:
            time.sleep(1.0)
            c2, p2 = _get(f"/predictions/{pid}")
            if c2 < 400 and isinstance(p2, dict) and p2.get("status") in ("succeeded", "failed", "canceled"):
                return PredictionRun(code, data, p2, None, " ".join(notes), waited)
        notes.append("Replicate has not confirmed that it stopped.")
        return PredictionRun(code, data, None, None, " ".join(notes), waited)

    def send(max_units):
        code, data = _post("/predictions", {"version": version, "input": inp})
        try:
            return follow(code, data, max_units)
        except Exception as exc:  # failure-policy: fail_closed -- reported, and charged
            # Created, so a failure while polling or cancelling it is not a
            # failure to send: it is reported, and the call is charged.
            return PredictionRun(code, data, None, (
                f"ERROR: poll failed ({type(exc).__name__}); use predict_get to check "
                f"prediction {data.get('id')}"), " ".join(notes), waited)

    return charged_call("replicate", send, budget=budget, label=label,
                        units={"request": 1}, measure=_measured, bounded=True)


def prediction_reply(run: PredictionRun, *, poll_hint: str, created_hint: str = "") -> str:
    """The plain reply for one prediction: its real final state, or that it
    is still running, after any note on waiting or cancelling."""
    data = run.created
    if run.code >= 400 or not isinstance(data, dict):
        return f"ERROR: run ({run.code}): {data}"
    pid = data.get("id")
    lead = f"{run.note}\n" if run.note else ""
    if not run.waited:
        return f"created prediction {pid} (status={data.get('status')}){created_hint}"
    if run.poll_error:
        return lead + run.poll_error
    if run.final is not None:
        return lead + _fmt_prediction(run.final)
    if "cancelled" in run.note:
        return lead + f"prediction {pid}: {poll_hint}"
    return lead + f"prediction {pid} still running after 90s; {poll_hint}"


def _fmt_prediction(p: dict) -> str:
    out = p.get("output")
    out_str = json.dumps(out, default=str)[:1500] if out is not None else "(none)"
    return (
        f"id:     {p.get('id')}\n"
        f"status: {p.get('status')}\n"
        f"error:  {p.get('error') or '(none)'}\n"
        f"output: {out_str}"
    )


def _op_run(args: dict, budget=None) -> str:
    model = (args.get("model") or "").strip()
    if not model:
        return "ERROR: run requires model"
    # owner/name[:version] -- reject anything that could traverse to a
    # different API path (model is interpolated into /models/{model}).
    owner_name = model.split(":", 1)[0]
    parts = owner_name.split("/")
    if (len(parts) != 2 or not all(parts) or ".." in owner_name
            or not all(c.isalnum() or c in "_.-" for p in parts for c in p)):
        return f"ERROR: invalid model {model!r} (expected owner/name[:version])"
    inp = args.get("input") if isinstance(args.get("input"), dict) else {}
    version = _resolve_version(model)
    if not version:
        return f"ERROR: could not resolve version for model {model!r}"
    run = run_prediction(version, inp, as_bool(args.get("wait")), budget)
    return prediction_reply(run, poll_hint="use predict_get to poll")


def _op_predict_get(args: dict) -> str:
    pid = (args.get("prediction_id") or "").strip()
    if not pid:
        return "ERROR: predict_get requires prediction_id"
    seg = safe_path_segment(pid)
    if seg is None:
        return "ERROR: predict_get requires a valid prediction_id"
    code, data = _get(f"/predictions/{seg}")
    if code == 404:
        return f"prediction {pid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: predict_get ({code}): {data}"
    return _fmt_prediction(data)


def _op_cancel(args: dict) -> str:
    pid = (args.get("prediction_id") or "").strip()
    if not pid:
        return "ERROR: cancel requires prediction_id"
    seg = safe_path_segment(pid)
    if seg is None:
        return "ERROR: cancel requires a valid prediction_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would cancel {pid}. Re-run with confirm=true."
    code, data = _post(f"/predictions/{seg}/cancel", {})
    if code >= 400:
        return f"ERROR: cancel ({code}): {data}"
    return f"cancelled {pid}"


def _op_models(args: dict) -> str:
    import httpx
    q = (args.get("query") or "").strip()
    if not q:
        return "ERROR: models requires query"
    # Replicate's catalog search is the HTTP QUERY method with the
    # plaintext search string as the body — GET /models is the
    # (unfiltered) list endpoint and ignores any query param, so it
    # would silently return the whole catalog instead of matches.
    # guarded_sender takes the URL first, so bind the method around it.
    r = _governed_sender(lambda url, **kw: httpx.request("QUERY", url, **kw))(
        f"{_API}/models",
        headers={"Authorization": f"Bearer {_token()}",
                 "Content-Type": "text/plain"},
        content=q, timeout=30.0,
    )
    code = r.status_code
    try:
        data = r.json()
    except ValueError:
        data = r.text[:300]
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: models ({code}): {data}"
    rows = data.get("results") or []
    if not rows:
        return "no models"
    return "\n".join(
        f"  {m.get('owner')}/{m.get('name')}  "
        f"{(m.get('description') or '')[:60]}"
        for m in rows[:25]
    )


def _run(args: dict[str, Any], budget=None) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed."
    try:
        if op == "run":
            return _op_run(args, budget)
        return {
            "predict_get": _op_predict_get,
            "cancel":      _op_cancel,
            "models":      _op_models,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except STOP_SIGNALS:
        raise
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Replicate request failed: {type(e).__name__}: {e}"


def replicate_tool(*, budget=None) -> Tool:
    return Tool(
        name="replicate",
        description=(
            "Replicate hosted ML models. ops: run (model + input "
            "[+wait to poll]), predict_get, cancel (confirm=true), "
            "models (catalog search). model = 'owner/name[:version]'. "
            "Auth: REPLICATE_API_TOKEN."
        ),
        input_schema=_RP_SCHEMA,
        fn=lambda args: _run(args, budget),
    )
