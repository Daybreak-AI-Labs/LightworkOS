"""Same exact local AI reviews and saved receipts for guarded Copilot."""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from . import local_runtime_service as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class ConfigurationInput(StrictInput):
    enabled: bool
    engine: Literal["llamacpp", "vllm", "tgi"]
    model: str = Field(min_length=1, max_length=1024)


def snapshot(request, _selection, *, action=None):
    current = native.state(request)
    details = {"server": current["state"], "program": current["engine"], "model": current["model"],
               "local_ai_on": current["enabled"], "next_step": current["blocked"] or current["message"]}
    fields, blocked = [], ""
    if action == "configure":
        choices = [{"value": value, "label": label} for value, label in native.model_choices()]
        fields = [{"name": "enabled", "label": "Allow local model serving", "kind": "boolean", "value": current["enabled"]},
                  {"name": "engine", "label": "Installed model server program", "kind": "select", "value": current["engine_choice"],
                   "choices": [{"value": key, "label": value} for key, value in native._LABELS.items()]},
                  {"name": "model", "label": "Existing local model", "kind": "select", "value": current["model_choice"], "choices": choices}]
        blocked = "No supported local model is available in this installation. Open Local AI to see what is required." if not choices else ""
    elif action and not current["can_" + action]:
        blocked = current["blocked"] or ("Turn on local model serving in Local AI first." if action == "start" and not current["enabled"] else current["message"])
    return Snapshot(current["revision"], "Current installed local AI and owned server state", current["message"],
                    details=details, fields=fields, blocked=blocked)


def prepare(request, _selection, arguments, *, action):
    review = native.prepare_configuration(request, **arguments) if action == "configure" else native.prepare(request, action)
    return Preview(review["summary"], native=review)


def _outcome(saved, *, replay=False):
    return Outcome({"unknown": "unconfirmed", "waiting": "queued", "refused": "unconfirmed"}.get(saved["state"], "replayed" if replay else "confirmed"),
                   saved["message"], {"request_status": {"unknown": "Result unknown", "started": "Start accepted", "stopped": "Stopped",
                     "saved": "Settings saved", "waiting": "Awaiting approval", "refused": "Not applied"}[saved["state"]]})


def execute(request, _selection, _arguments, review, _operation_id):
    return _outcome(native.apply(request, review))


def recover(request, _selection, _arguments, review, _operation_id):
    saved = native.receipt(request, review["id"])
    return _outcome(saved, replay=True) if saved else None


def entries():
    shared = {"family": "models", "direct_ui": native.PAGE, "pages": (native.PAGE, "/settings", "/settings/all")}
    result = [Adapter("local_ai.status", "Check local AI status", input_model=EmptyInput, snapshot=snapshot,
                      prepare=lambda request, selection, _args: Preview(snapshot(request, selection).summary, native=snapshot(request, selection).details), **shared),
              Adapter("local_ai.health", "Check local AI service health", input_model=EmptyInput, snapshot=snapshot,
                      prepare=lambda request, _selection, _args: Preview("A bounded check of this computer's local service, without an AI request.", native=native.health(request)), **shared)]
    for action, label in (("configure", "Set up local AI"), ("start", "Start local AI"), ("stop", "Stop local AI")):
        result.append(Adapter("local_ai." + action, label, input_model=ConfigurationInput if action == "configure" else EmptyInput,
            snapshot=lambda request, selection, action=action: snapshot(request, selection, action=action),
            prepare=lambda request, selection, arguments, action=action: prepare(request, selection, arguments, action=action),
            execute=execute, recover=recover, read_recovery=recover, **shared))
    return result
