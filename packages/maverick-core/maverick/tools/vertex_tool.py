"""Vertex AI tool — Google Cloud Vertex generate + custom-endpoint predict.

Calls Vertex AI over REST: Gemini ``generateContent`` and custom-model
``predict``. Uses a pre-acquired OAuth access token (e.g. from
``gcloud auth print-access-token``) so no GCP SDK / ADC is required.

Auth:
  - ``VERTEX_ACCESS_TOKEN``  (OAuth 2 Bearer)
  - ``VERTEX_PROJECT``       (GCP project id)
  - ``VERTEX_LOCATION``      (region; default us-central1)

ops:
  - generate(model, prompt)            — Gemini generateContent
  - predict(endpoint_id, instances)    — custom deployed endpoint
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["generate", "predict"]},
        "model": {"type": "string", "description": "e.g. gemini-2.5-pro (generate)."},
        "prompt": {"type": "string"},
        "endpoint_id": {"type": "string", "description": "deployed endpoint id (predict)."},
        "instances": {"type": "array", "description": "predict instances."},
    },
    "required": ["op"],
}

_DEFAULT_LOCATION = "us-central1"
_DEFAULT_MODEL = "gemini-2.5-pro"


def _config() -> tuple[str, str, str]:
    tok = os.environ.get("VERTEX_ACCESS_TOKEN", "").strip()
    proj = os.environ.get("VERTEX_PROJECT", "").strip()
    loc = os.environ.get("VERTEX_LOCATION", "").strip() or _DEFAULT_LOCATION
    if not tok or not proj:
        raise RuntimeError("Vertex requires VERTEX_ACCESS_TOKEN + VERTEX_PROJECT.")
    return tok, proj, loc


def _headers() -> dict[str, str]:
    tok, _p, _l = _config()
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}


def _base() -> str:
    _t, proj, loc = _config()
    return (f"https://{loc}-aiplatform.googleapis.com/v1/projects/{proj}"
            f"/locations/{loc}")


def _op_generate(model: str, prompt: str) -> str:
    if not prompt:
        return "ERROR: generate requires prompt"
    import httpx
    model = model or _DEFAULT_MODEL
    url = f"{_base()}/publishers/google/models/{model}:generateContent"
    body = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}
    r = _governed_sender(httpx.post)(url, headers=_headers(), json=body, timeout=120.0)
    try:
        data = r.json()
    except ValueError:
        return f"ERROR: generate ({r.status_code}): {(r.text or '')[:500]}"
    if r.status_code >= 400:
        return f"ERROR: generate ({r.status_code}): {data.get('error', data)}"
    cands = data.get("candidates") or []
    if not cands:
        return f"no candidates: {json.dumps(data, default=str)[:500]}"
    parts = (cands[0].get("content") or {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts)
    return text or json.dumps(cands[0], default=str)[:2000]


def _op_predict(endpoint_id: str, instances: list) -> str:
    if not endpoint_id or not instances:
        return "ERROR: predict requires endpoint_id and instances"
    import httpx
    url = f"{_base()}/endpoints/{endpoint_id}:predict"
    r = _governed_sender(httpx.post)(url, headers=_headers(), json={"instances": instances}, timeout=120.0)
    try:
        data = r.json()
    except ValueError:
        return f"ERROR: predict ({r.status_code}): {(r.text or '')[:500]}"
    if r.status_code >= 400:
        return f"ERROR: predict ({r.status_code}): {data.get('error', data)}"
    return json.dumps(data.get("predictions", data), default=str)[:3000]


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    # Enterprise egress lock. enterprise.py's headline claim is that under
    # MAVERICK_ENTERPRISE "sensitive data physically cannot reach a third-party
    # API", enforced "via enterprise_egress_denial at each tool's request".
    # This tool posts prompts and instances to *-aiplatform.googleapis.com and
    # did not call it -- so a default-registered tool contradicted the single
    # property enterprise mode is sold on. Checked before any request is built,
    # so no prompt is assembled for a host we may not reach.
    # Built from the location alone, not _base(): _base() requires credentials
    # and raises without them, and an egress decision must not depend on
    # whether the caller happens to be configured. The host is what the lock
    # cares about, and it is fully determined by the location.
    from ..enterprise import enterprise_egress_denial

    _loc = os.environ.get("VERTEX_LOCATION", "").strip() or _DEFAULT_LOCATION
    if denial := enterprise_egress_denial(
            f"https://{_loc}-aiplatform.googleapis.com/", tool="vertex"):
        return f"ERROR: {denial}"

    instances = args.get("instances") if isinstance(args.get("instances"), list) else []
    try:
        if op == "generate":
            return _op_generate((args.get("model") or "").strip(),
                                (args.get("prompt") or "").strip())
        if op == "predict":
            return _op_predict((args.get("endpoint_id") or "").strip(), instances)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Vertex request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def vertex_tool() -> Tool:
    return Tool(
        name="vertex",
        description=(
            "Google Cloud Vertex AI over REST. ops: generate (Gemini "
            "generateContent), predict (custom deployed endpoint). Auth: "
            "VERTEX_ACCESS_TOKEN + VERTEX_PROJECT (+ VERTEX_LOCATION, "
            "default us-central1)."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
