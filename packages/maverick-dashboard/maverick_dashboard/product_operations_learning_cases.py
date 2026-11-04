"""Copilot uses the native reviewed self-coaching question authoring service."""
from __future__ import annotations

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from . import learning_test_cases_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot


def snapshot(request, _selection):
    state = native.current(request)
    return Snapshot(state["revision"], "Current shared self-coaching questions and available models",
        state["scope"], details={"Saved questions": state["total"]}, blocked=state["blocked"] or
        ("Choose an available model in All settings before adding a question." if not state["models"] else ""),
        fields=[{"name": "model", "label": "Model", "kind": "select", "required": True,
                 "choices": [{"value": row["value"], "label": row["label"]} for row in state["models"]]},
                {"name": "question", "label": "Question or task", "kind": "textarea", "required": True, "max_length": 4000},
                {"name": "expected", "label": "Expected answer", "kind": "textarea", "required": True, "max_length": 4000}])


def prepare(request, _selection, arguments):
    prepared = native.prepare_case(request, arguments)
    return Preview("Add this one question to the selected model's shared self-coaching collection. No check runs or AI spending occurs.",
                   changes=native.changes(prepared), native=prepared)


def _details(row):
    result = {"Current collection": row.get("current", "No original saved request was found."), "Scope": native.SCOPE}
    if "question" in row:
        result.update({"Model": row["model"], "Question": row["question"], "Expected answer": row["expected"],
                       "Open original save": {"href": "/learned?learning_case_request=" + row["operation"] + "#learning-test-questions", "label": "Open original save"}})
    return result


def _checked(arguments, prepared):
    values = native.CaseIn.model_validate(arguments).model_dump()
    if prepared.get("case") != values:
        raise HTTPException(409, "The question changed after review. Prepare it again before saving.")


def execute(request, _selection, arguments, prepared, operation):
    _checked(arguments, prepared)
    row = native.save_case(request, prepared, operation)
    return Outcome("confirmed" if row["confirmed"] else "unconfirmed", row["message"], _details(row))


def recover(request, _selection, arguments, prepared, operation, *, read_only=False):
    _checked(arguments, prepared)
    existing = native._owned(request, operation)
    if existing is None and not read_only:
        return None
    if existing is not None:
        from maverick.governed_operations import digest

        from .learning_ops_api import _actor
        if existing["request_digest"] != digest({"operation": operation, "prepared": prepared, "actor": _actor(request)}):
            raise HTTPException(409, "This request belongs to another reviewed question. Read its original result.")
    row = native.original_request(request, operation)
    return Outcome("replayed" if row["confirmed"] else "unconfirmed", row["message"], _details(row))


def _selected(request, selection):
    if selection.get("kind") != "learning_test_case":
        raise HTTPException(409, "Choose a saved question in Learned before correcting or retiring it.")
    values = native.SelectedIn.model_validate({"model": selection.get("model"), "reference": selection.get("reference")})
    return native.selected_case(request, values.model, values.reference)


def change_snapshot(request, selection, *, retire=False):
    state = native.current(request)
    try:
        case = _selected(request, selection)
    except (HTTPException, ValueError):
        return Snapshot(state["revision"], "Current shared self-coaching questions", native.SCOPE,
                        blocked="Choose an available saved question in Learned before correcting or retiring it.")
    return Snapshot(case["revision"], "The exact selected self-coaching question", native.SCOPE,
                    details={"Model": case["model_label"], "Question": case["question"], "Expected answer": case["expected"]},
                    blocked=state["blocked"], fields=[] if retire else [
                      {"name": "question", "label": "Corrected question or task", "kind": "textarea", "value": case["question"], "required": True, "max_length": 4000},
                      {"name": "expected", "label": "Corrected expected answer", "kind": "textarea", "value": case["expected"], "required": True, "max_length": 4000}])


class CorrectSelected(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    question: str = Field(min_length=1, max_length=4000)
    expected: str = Field(min_length=1, max_length=4000)


class RetireSelected(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def setup_snapshot(request, _selection):
    state = native.setup_state(request)
    return Snapshot(state["revision"], "Current installation-owned learning-question setting and storage rules", native.SCOPE,
                    details={"Chosen storage": state["storage"], "Location": "Lightwork chooses its managed learning location for you."},
                    blocked=state["blocked"])


def _task_form_current(request):
    from .learning_task_examples import catalog

    choices = catalog(request, offset=0)
    state = native.current(request)
    if state["context"] != choices["context"]:
        raise HTTPException(409, "Your account or workspace changed. Open the current learning-question controls again.")
    return choices, state


def task_form_snapshot(request, _selection):
    from maverick.governed_operations import digest

    choices, state = _task_form_current(request)
    return Snapshot(digest([choices, state]), "Your current completed-work question controls",
        "Open the ordinary task picker to choose your own completed work, edit its question and expected answer, "
        "and review source use before saving. Opening copies nothing and runs no AI.",
        blocked=state["blocked"])


def task_form_prepare(request, selection, _arguments):
    from maverick.governed_operations import digest

    current = task_form_snapshot(request, selection)
    choices, state = _task_form_current(request)
    if digest([choices, state]) != current.revision:
        raise HTTPException(409, "Your task choices or learning settings changed. Open the current controls again.")
    if current.blocked:
        raise HTTPException(409, current.blocked)
    return Preview(current.summary, native={"learning_task_question_review": {
        "scope": "current_page", "context": choices["context"],
    }})


def question_check_snapshot(request, _selection):
    from maverick.governed_operations import digest

    from .learning_question_checks import catalog

    current = catalog(request)
    return Snapshot(digest(current), "Current question-check controls",
        "Open the complete question check to choose saved questions, review AI use and limits, "
        "or read the original request. Opening starts no check and removes no question.")


def question_check_prepare(request, selection, _arguments):
    from maverick.governed_operations import digest

    from .learning_question_checks import catalog

    state = question_check_snapshot(request, selection)
    current = catalog(request)
    if digest(current) != state.revision:
        raise HTTPException(409, "Your question-check settings or access changed. Open the current controls again.")
    return Preview(state.summary, native={"learning_question_check_form": {"context": current["context"]}})


def import_snapshot(request, _selection):
    from .learning_ops_api import import_controls
    current = import_controls(request)
    return Snapshot(current["revision"], "Current learning-question import controls", current["notice"],
                    details={"Saved questions": current["total"], "File": "Choose your file in the ordinary form. Opening imports nothing."})


def import_prepare(request, selection, _arguments):
    from .learning_ops_api import import_controls
    state = import_snapshot(request, selection)
    current = import_controls(request)
    if current["revision"] != state.revision:
        raise HTTPException(409, "Your learning questions, storage or access changed. Open the current import controls again.")
    return Preview(state.summary, native={"learning_case_import_form": {"context": current["context"]}})


def setup_prepare(request, _selection, _arguments):
    prepared = native.prepare_setup(request)
    return Preview("Set up the existing learning-question collection. No learning system is turned on and no AI runs.",
                   changes=native.setup_changes(prepared), native=prepared)


def _setup_details(row):
    return {"Current readiness": row["current"], "Scope": row["scope"],
            "Open original setup": {"href": "/learned?learning_case_setup=" + row["operation"] + "#learning-test-questions", "label": "Open original setup"}}


def setup_execute(request, _selection, _arguments, prepared, operation):
    row = native.save_setup(request, prepared, operation)
    return Outcome("confirmed" if row["confirmed"] else "unconfirmed", row["message"], _setup_details(row))


def setup_recover(request, _selection, _arguments, prepared, operation, *, read_only=False):
    if not read_only and native._setup_store().get("LCS-" + operation) is None:
        return None
    row = native.setup_original(request, operation, prepared=prepared)
    return Outcome("replayed" if row["confirmed"] else "unconfirmed", row["message"], _setup_details(row))


def change_prepare(request, selection, arguments, *, retire=False):
    case = _selected(request, selection)
    values = {"model": case["model"], "reference": case["reference"], **arguments}
    prepared = native.prepare_change(request, values, "retire" if retire else "correct", context=case["context"], revision=case["revision"])
    return Preview("Retire this exact shared question from future checks." if retire else "Correct this exact shared question. Other saved information stays in place.",
                   changes=native.changes(prepared), native=prepared)


def _checked_change(selection, arguments, prepared):
    case = prepared.get("case", {})
    if (selection.get("kind") != "learning_test_case" or selection.get("model") != case.get("model")
            or selection.get("reference") != case.get("reference")
            or prepared.get("action") == "correct" and any(case.get(key) != arguments.get(key) for key in ("question", "expected"))):
        raise HTTPException(409, "The selected question changed after review. Review it again.")


def change_execute(request, selection, arguments, prepared, operation):
    _checked_change(selection, arguments, prepared)
    row = native.save_change(request, prepared, operation)
    return Outcome("confirmed" if row["confirmed"] else "unconfirmed", row["message"], _details(row))


def change_recover(request, selection, arguments, prepared, operation, *, read_only=False):
    _checked_change(selection, arguments, prepared)
    existing = native._owned(request, operation)
    if existing is None and not read_only:
        return None
    if existing is not None:
        from maverick.governed_operations import digest

        from .learning_ops_api import _actor
        if existing["request_digest"] != digest({"operation": operation, "prepared": prepared, "actor": _actor(request)}):
            raise HTTPException(409, "This request belongs to another reviewed question change.")
    row = native.original_request(request, operation)
    return Outcome("replayed" if row["confirmed"] else "unconfirmed", row["message"], _details(row))


def entries():
    return (Adapter("learning.import_question_file_form", "Review a learning-question file", "learning", "/learned#learning-case-import",
        ("/learned",), EmptyInput, import_snapshot, import_prepare,
        aliases=("import my learning questions", "review a test question file", "open question import controls")),
        Adapter("learning.question_check_form", "Review a complete question check", "learning", "/learned#learning-question-checks",
        ("/learned",), EmptyInput, question_check_snapshot, question_check_prepare,
        aliases=("check my learning questions", "check question usefulness", "review question checks")),
        Adapter("learning.task_question_form", "Turn completed work into a learning question", "learning", native.PAGE,
        ("/learning", "/learned"), EmptyInput, task_form_snapshot, task_form_prepare,
        aliases=("learn from my completed work", "use a completed task as a test question", "open task question controls")),
        Adapter("learning.setup_test_questions", "Set up learning questions", "learning", native.PAGE,
        ("/learning", "/learned"), RetireSelected, setup_snapshot, setup_prepare, setup_execute, setup_recover,
        read_recovery=lambda r, s, a, p, o: setup_recover(r, s, a, p, o, read_only=True)),
        Adapter("learning.add_test_question", "Add a self-coaching test question", "learning", native.PAGE,
        ("/learning", "/learned"), native.CaseIn, snapshot, prepare, execute, recover,
        read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True)),
        Adapter("learning.correct_test_question", "Correct the selected self-coaching question", "learning", native.PAGE,
          ("/learning", "/learned"), CorrectSelected, change_snapshot, change_prepare, change_execute, change_recover,
          read_recovery=lambda r, s, a, p, o: change_recover(r, s, a, p, o, read_only=True)),
        Adapter("learning.retire_test_question", "Retire the selected self-coaching question", "learning", native.PAGE,
          ("/learning", "/learned"), RetireSelected, lambda r, s: change_snapshot(r, s, retire=True),
          lambda r, s, a: change_prepare(r, s, a, retire=True), change_execute, change_recover,
          read_recovery=lambda r, s, a, p, o: change_recover(r, s, a, p, o, read_only=True)))
