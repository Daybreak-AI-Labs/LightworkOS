"""Protected native answer-entry handoff and original scoring readback."""
from urllib.parse import urlencode

from fastapi import HTTPException
from maverick.governed_operations import digest
from maverick.training.environments import load_environment
from pydantic import BaseModel, ConfigDict, Field

from . import model_answer_scoring as native
from .plain_labels import model_label
from .product_operations import Adapter, Preview, Snapshot


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    task_set: str = Field(min_length=1, max_length=120)
    split: str = Field(min_length=1, max_length=20)
    model: str = Field(default="", max_length=200)


class Empty(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def snapshot(request, _selection):
    context = native.authority(request)
    models = native._models()
    source = [load_environment(name).digest for name in native.TITLES]
    native.authority(request, context)
    return Snapshot(digest([context, source, models]), "Current published task questions and reported model labels", native.NOTICE,
        fields=[{"name": "task_set", "label": "Task set", "kind": "select", "required": True,
                 "choices": [{"value": key, "label": value} for key, value in native.TITLES.items()]},
                {"name": "split", "label": "Questions", "kind": "select", "required": True,
                 "choices": [{"value": key, "label": value} for key, value in native.SPLITS.items()]},
                {"name": "model", "label": "Reported answer model (optional; not verified)", "kind": "select", "value": "",
                 "choices": [{"value": "", "label": "Not specified"}] + [{"value": value, "label": model_label(value)} for value in models]}])


def prepare(request, _selection, arguments):
    state, _pack = native.current(request, arguments["task_set"], arguments["split"])
    if arguments["model"] and arguments["model"] not in {row["value"] for row in state["models"]}:
        raise HTTPException(409, "Refresh the currently available reported model labels.")
    query = urlencode({"scoring_task_set": arguments["task_set"], "scoring_split": arguments["split"],
                       "scoring_model": arguments["model"]})
    return Preview(native.NOTICE, native={"Task set": state["title"], "Questions": state["questions_label"],
        "Supplied answers": "Enter and review each answer in the protected ordinary form. This does not call AI or start scoring.",
        "model_answer_form": {"task_set": arguments["task_set"], "split": arguments["split"],
                              "model": arguments["model"], "context": state["context"]},
        "Open answer form": {"href": "/learning?" + query + "#lo-mi-answer-h", "label": "Enter and review answers"}})


def result_snapshot(request, selection):
    native.authority(request, current_settings=False)
    if selection.get("kind") != "model_answer_score" or not selection.get("operation"):
        return Snapshot(digest([native.authority(request), "no-selected-score"]), "Original provided-answer scoring records",
                        native.NOTICE, blocked="Choose Check original scoring result in the Learning answer form first.")
    row = native.original(request, selection["operation"])
    return Snapshot(digest(row), "Original request and retained native scoring task", row["message"])


def result_prepare(request, selection, _arguments):
    row = native.original(request, selection["operation"])
    details = {"Original request": row["message"], "Meaning of the result": native.NOTICE}
    if row.get("job"):
        job = row["job"]
        details["Task status"] = native.native._JOB_STATES.get(job["state"], "Result unavailable")
        if job.get("result"):
            result = job["result"]
            details["Supplied answers"] = {"Passed": result["passed"], "Questions": result["questions"],
                                            "Score": str(round(result["score"] * 100)) + "%", "Answer checks": [{
                                                "Question": answer["question"], "Result": "Passed" if answer["passed"] else "Needs review",
                                                "Answer match": str(round(answer["answer_match"] * 100)) + "%",
                                                "Supporting evidence": str(round(answer["evidence_match"] * 100)) + "%"} for answer in result["answers"]]}
        if job.get("problem"):
            details["Current problem"] = job["problem"]
    details["Open original result"] = {"href": "/learning?scoring_request=" + row["operation"] + "#lo-mi-answer-h", "label": "Read original scoring result"}
    return Preview(row["message"], native=details)


def entries():
    common = {"family": "learning", "direct_ui": native.PAGE, "pages": ("/learning",)}
    return (Adapter("learning.score_provided_answers", "Enter answers for a task-set check", input_model=Choices,
                    snapshot=snapshot, prepare=prepare, **common),
            Adapter("learning.read_provided_answer_score", "Read the selected original answer check", input_model=Empty,
                    snapshot=result_snapshot, prepare=result_prepare, **common))
