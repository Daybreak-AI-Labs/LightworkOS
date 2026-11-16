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

``generate`` names no model of its own (users own model choice) and refuses a
model outside ``[access] allowed_models``.

Every request is model spend, so it is charged to the run budget (kernel rule
3): ``budget.check()`` runs before it and the usage is recorded after it. The
price is the one set for the exact route in Settings (``vertex:<model id>``
for ``generate``, ``vertex:endpoints/<endpoint id>`` for ``predict``), else a
tracked price for that route, else the safety ceiling
(``budget.metered_tool_quote``); no Vertex price is written here. Token counts
come from the reply's ``usageMetadata``; a reply without them (a custom
endpoint's usually has none), error replies included, is charged an estimate
from the request and reply text length and marked estimated. The same charge
settles the provider spend receipt for ``vertex``, so a
``[budget.provider_caps] vertex`` cap is enforced. A caller with no run budget
is refused before anything is sent.
"""
from __future__ import annotations

import json
import logging
import math
import os
from typing import Any

from ..budget import (
    BudgetExceeded,
    UsageAccountingError,
    _coerce_count,
    metered_tool_quote,
    record_tool_tokens,
)
from ..governed_http import guarded_sender as _governed_sender
from ..provider_cost_cap import (
    ProviderAccountingUnavailable,
    ProviderCapExceeded,
    metered_provider_call,
)
from . import Tool, safe_path_segment

log = logging.getLogger(__name__)

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["generate", "predict"]},
        "model": {"type": "string", "description": (
            "Vertex model id to call (generate). Required; when [access] "
            "allowed_models is set it must list vertex:<model id>.")},
        "prompt": {"type": "string"},
        "endpoint_id": {"type": "string", "description": "deployed endpoint id (predict)."},
        "instances": {"type": "array", "description": "predict instances."},
    },
    "required": ["op"],
}

_DEFAULT_LOCATION = "us-central1"


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


def _price_route(name: str) -> str | None:
    """``vertex:<name>``, the route a price is set for, or ``None`` when the
    name cannot label a charge (too long, or a control character)."""
    route = f"vertex:{name}"
    if len(route) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in route):
        return None
    return route


def _estimated_tokens(text: str) -> int:
    """About four characters per token, rounded up, as the model adapters do."""
    return math.ceil(len(text) / 4)


def _reported_usage(response) -> tuple[int, int] | None:
    """``(input, output)`` tokens from a reply's ``usageMetadata``, else ``None``.

    Thinking tokens are billed as output, and so is anything else the total
    holds beyond the prompt. A malformed count stops the run
    (``UsageAccountingError``) rather than charging a paid call as zero.
    """
    try:
        data = response.json()
    except ValueError:
        return None
    usage = data.get("usageMetadata") if isinstance(data, dict) else None
    if not isinstance(usage, dict) or (
            usage.get("promptTokenCount") is None and usage.get("totalTokenCount") is None):
        return None
    prompt = _coerce_count(usage.get("promptTokenCount"))
    reply = (_coerce_count(usage.get("candidatesTokenCount"))
             + _coerce_count(usage.get("thoughtsTokenCount")))
    return prompt, max(reply, _coerce_count(usage.get("totalTokenCount")) - prompt)


def _charge(budget, quote, response, sent: str) -> dict[str, Any]:
    """Record one reply's usage on the run budget.

    Returns the charge, whether its token counts were estimated, and the cap
    error it raised, if any: the caller settles the receipt before stopping.
    """
    usage = _reported_usage(response)
    estimated = usage is None
    if usage is None:
        reply = getattr(response, "text", "")
        usage = (_estimated_tokens(sent),
                 _estimated_tokens(reply if isinstance(reply, str) else ""))
    stop = None
    try:
        charge = record_tool_tokens(budget, quote, *usage, estimated=estimated)
    except BudgetExceeded as exc:
        charge = getattr(exc, "token_charge", None)
        if charge is None:
            raise
        stop = exc
    return {"charge": charge, "estimated": estimated, "stop": stop}


def _post(url: str, body: dict, category: str, *, budget, price_route: str):
    """One paid Vertex request, charged to the run budget and to the provider
    spend receipt at the same price."""
    if budget is None:
        raise RuntimeError(
            "Vertex calls are charged to a run's spending limit, and this call has "
            "none (a flow's tool step, for example). Call Vertex from an agent "
            "step instead; nothing was sent")
    import httpx
    headers = _headers()
    budget.check()
    quote = metered_tool_quote(price_route)
    sent = json.dumps(body, default=str)
    # The reply's size is unknown before the call, so the hold covers the
    # request; the reply is charged when it arrives.
    projected = _estimated_tokens(sent) * quote.input_per_mtok / 1_000_000
    outcome: dict[str, Any] = {}

    def send():
        response = _governed_sender(httpx.post)(url, headers=headers, json=body, timeout=120.0)
        outcome.update(_charge(budget, quote, response, sent))
        return response

    def settlement(_response):
        charge = outcome["charge"]
        observed = charge.pricing_evidence["verified"] and not outcome["estimated"]
        return charge.dollars, "observed" if observed else "estimated", charge.pricing_evidence

    held = budget.reserve(projected)
    try:
        response = metered_provider_call(
            "vertex", send, projected_dollars=projected, settlement=settlement,
            organization_budget=budget,
            category=category, parent_category=category, service="vertex",
        )
    finally:
        budget.release(held)
    if outcome.get("stop") is not None:
        raise outcome["stop"]
    return response


def _op_generate(model: str, prompt: str, budget) -> str:
    if not prompt:
        return "ERROR: generate requires prompt"
    if not model:
        return "ERROR: generate requires model (the Vertex model id to call)"
    from ..llm import ModelNotAllowedError, require_model_allowed
    try:
        require_model_allowed(f"vertex:{model}")
    except (ModelNotAllowedError, ValueError) as e:
        return f"ERROR: {e}"
    seg = safe_path_segment(model)
    price_route = _price_route(model)
    if seg is None or price_route is None:
        return "ERROR: generate requires a valid model"
    url = f"{_base()}/publishers/google/models/{seg}:generateContent"
    body = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}
    r = _post(url, body, "generation", budget=budget, price_route=price_route)
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


def _op_predict(endpoint_id: str, instances: list, budget) -> str:
    if not endpoint_id or not instances:
        return "ERROR: predict requires endpoint_id and instances"
    seg = safe_path_segment(endpoint_id)
    price_route = _price_route(f"endpoints/{endpoint_id}")
    if seg is None or price_route is None:
        return "ERROR: predict requires a valid endpoint_id"
    url = f"{_base()}/endpoints/{seg}:predict"
    r = _post(url, {"instances": instances}, "inference", budget=budget, price_route=price_route)
    try:
        data = r.json()
    except ValueError:
        return f"ERROR: predict ({r.status_code}): {(r.text or '')[:500]}"
    if r.status_code >= 400:
        return f"ERROR: predict ({r.status_code}): {data.get('error', data)}"
    return json.dumps(data.get("predictions", data), default=str)[:3000]


def _run(args: dict[str, Any], *, budget=None) -> str:
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
                                (args.get("prompt") or "").strip(), budget)
        if op == "predict":
            return _op_predict((args.get("endpoint_id") or "").strip(), instances, budget)
    except (ProviderAccountingUnavailable, ProviderCapExceeded, BudgetExceeded,
            UsageAccountingError):
        # Stop signals must propagate or the spending limit is not enforced.
        raise
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Vertex request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def vertex_tool(*, budget=None) -> Tool:
    return Tool(
        name="vertex",
        description=(
            "Google Cloud Vertex AI over REST. ops: generate (Gemini "
            "generateContent), predict (custom deployed endpoint). Auth: "
            "VERTEX_ACCESS_TOKEN + VERTEX_PROJECT (+ VERTEX_LOCATION, "
            "default us-central1). Each call is charged to the run budget at "
            "the price set in Settings for vertex:<model id> (predict: "
            "vertex:endpoints/<endpoint id>), else a tracked price, else a "
            "safety ceiling."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(args, budget=budget),
    )
