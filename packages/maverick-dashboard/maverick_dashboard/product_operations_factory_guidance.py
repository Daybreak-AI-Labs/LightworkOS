"""Same complete factory controls and exact originals through Copilot."""
from maverick.governed_operations import digest
from pydantic import Field

from . import factory_guidance as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class OriginalIn(StrictInput):
    operation: str = Field(pattern=r"^[a-f0-9]{32}$")


class CompareIn(StrictInput):
    correction: str = Field(min_length=1, max_length=256)
    packs: list[str] = Field(min_length=2, max_length=64)
    min_support: int = Field(default=3, ge=2, le=1000)
    dollars: float = Field(ge=0, le=5)
    seconds: int = Field(ge=15, le=300)
    authorize_input_use: bool


def state(request, _selection):
    row = native.catalog(request)
    return Snapshot(digest(row), "Current agent-building guidance and permitted comparison requests", native.NOTICE,
                    details={"Suggested changes": len(row["corrections"]), "Current AI service": row["model"]},
                    fields=[{"name": "correction", "label": "Suggested guidance", "kind": "select", "required": True,
                             "choices": [{"value": item["key"], "label": item["guidance"]} for item in row["corrections"] if item["supported"]]},
                            {"name": "packs", "label": "Reported requests (choose only requests for the selected suggestion)", "kind": "multiselect", "presentation": "checkboxes", "required": True,
                             "choices": [{"value": name, "label": name.replace("_", " ")} for name in sorted({name for item in row["corrections"] if item["supported"] for name in item["packs"]})]},
                            {"name": "min_support", "label": "Minimum agents reporting the problem", "kind": "select", "value": 3,
                             "choices": [{"value": value, "label": str(value) + " agents"} for value in (2, 3, 5)]},
                            {"name": "dollars", "label": "Maximum AI spending in dollars", "kind": "number", "value": .5},
                            {"name": "seconds", "label": "Maximum time", "kind": "select", "value": 120,
                             "choices": [{"value": value, "label": str(value // 60) + " minutes"} for value in (60, 120, 300)]},
                            {"name": "authorize_input_use", "label": "Allow complete selected descriptions and goals to be sent to the current AI service; expected tool is a reported check", "kind": "boolean", "value": False}],
                    blocked="Turn on agent-building improvements on Learning before a new comparison." if not row["enabled"] else "")


def form_state(request, selection):
    current = state(request, selection)
    return Snapshot(current.revision, current.source, current.summary, details=current.details, blocked=current.blocked)


def form(request, _selection, _arguments):
    native.catalog(request)
    return Preview("Choose a current suggestion and named requests in the complete ordinary form. Opening it starts no work.",
                   native={"factory_guidance_author": {"scope": "current_page"},
                           "Open agent-building review": {"href": native.PAGE, "label": "Review agent-building guidance"}})


def compare_prepare(request, _selection, arguments):
    state = native.catalog(request, arguments["min_support"])
    row = native.review(request, "compare", {**arguments, "context": state["context"], "revision": state["revision"]})
    return Preview(native.NOTICE, changes=row["changes"], native=row)


def original_state(request, _selection):
    row = native.history(request)
    return Snapshot(digest([row["context"], row["requests"]]), "Your retained comparisons and adoptions", "Read the original without repeating its work.",
                    fields=[{"name": "operation", "label": "Original agent-building decision", "kind": "select", "required": True, "choices": row["requests"]}])


def adopt_prepare(request, _selection, arguments):
    row = native.review(request, "adopt", arguments)
    return Preview(native.NOTICE, changes=row["changes"], native=row)


class RestoreIn(StrictInput):
    adoption: str = Field(pattern=r"^[a-f0-9]{32}$")


def restore_state(request, _selection):
    row = native.restore_options(request)
    return Snapshot(digest(row), "Your most recent agent-building guidance change", native.RESTORE_NOTICE,
                    fields=[{"name": "adoption", "label": "Guidance change to undo", "kind": "select", "required": True, "choices": row["choices"]}],
                    blocked=row["notice"] if not row["choices"] else "")


def restore_prepare(request, _selection, arguments):
    row = native.review(request, "restore", arguments)
    return Preview(native.RESTORE_NOTICE, changes=row["changes"], native=row)


def outcome(row):
    details = {"Original request": row["message"], "Meaning and limits": native.NOTICE}
    result = row.get("result", {})
    for key, label in {"samples": "Complete paired requests", "baseline_score": "Current guidance tool-check score",
                       "candidate_score": "Suggested guidance tool-check score", "effect_ci_low": "Conservative difference estimate", "adopted": "Guidance adopted", "restored": "Earlier guidance restored"}.items():
        if key in result:
            details[label] = result[key]
    if row.get("job", {}).get("problem"):
        details["Saved problem"] = row["job"]["problem"]
    details["Read full original"] = {"href": "/learning?factory_original=" + row["operation"] + "#lo-factory", "label": "Read the full original comparison or adoption"}
    return Outcome("confirmed" if row["confirmed"] else "queued" if row.get("job", {}).get("worker_available") else "unconfirmed", row["message"], details)


def execute(request, _selection, _arguments, prepared, _operation):
    return outcome(native.apply(request, prepared["token"], confirmed=True))


def recover(request, _selection, _arguments, prepared, _operation, *, read_only=False):
    if not read_only and native._job(request, prepared["operation"]) is None:
        return None
    return outcome(native.original(request, prepared["operation"]))


def original_prepare(request, _selection, arguments):
    row = native.original(request, arguments["operation"])
    result = outcome(row)
    return Preview(result.message, native=result.details)


def entries():
    common = {"family": "learning", "pages": ("/learning",), "direct_ui": native.PAGE}
    writes = {"execute": execute, "recover": recover,
              "read_recovery": lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), "review_max_bytes": 200000}
    return (Adapter("learning.factory_guidance_form", "Review improvements to new agent building", input_model=EmptyInput,
                    snapshot=form_state, prepare=form, aliases=("improve how new agents are built",), **common),
            Adapter("learning.factory_guidance_check", "Compare selected agent-building guidance", input_model=CompareIn,
                    snapshot=state, prepare=compare_prepare, **writes, **common),
            Adapter("learning.factory_guidance_adopt", "Adopt checked agent-building guidance", input_model=OriginalIn,
                    snapshot=original_state, prepare=adopt_prepare, **writes, **common),
            Adapter("learning.factory_guidance_restore", "Restore earlier agent-building guidance", input_model=RestoreIn,
                    snapshot=restore_state, prepare=restore_prepare, **writes, **common),
            Adapter("learning.factory_guidance_original", "Read original agent-building result", input_model=OriginalIn,
                    snapshot=original_state, prepare=original_prepare, **common))
