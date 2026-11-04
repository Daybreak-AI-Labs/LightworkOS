"""Personal Today layout is a reviewed native preference operation."""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from . import preferences_api as native
from . import product_operations_preferences as preferences
from . import today_projection as projection
from .product_errors import product_error
from .product_operations import Adapter, EmptyInput, Preview, Snapshot, StrictInput


class Layout(StrictInput):
    action: Literal["show", "hide", "move_up", "move_down", "pin_template", "unpin_template", "period"]
    item: str = Field(max_length=179)


def snapshot(request, selection):
    state = native._state(request)
    templates = projection.template_choices(request)
    cards = [{"value": key, "label": label} for key, label in projection.CARDS.items()]
    template_items = [{"value": key, "label": row["title"]} for key, row in templates.items()]
    options = dict.fromkeys(("show", "hide", "move_up", "move_down"), cards)
    options.update({"pin_template": template_items, "unpin_template": template_items,
                    "period": [{"value": str(days), "label": f"{days} days"} for days in (1, 7, 30)]})
    return Snapshot(state["revision"], "Your account preferences in this workspace", "Arrange Today without changing work execution or mandatory decision reminders.",
        {key: state["values"][key] for key in ("today_cards", "today_days", "template_favorites")},
        [{"name": "action", "label": "Layout change", "kind": "select", "required": True,
          "choices": [{"value": key, "label": key.replace("_", " ").capitalize()} for key in options]},
         {"name": "item", "label": "Card, template or period", "kind": "text", "depends_on": "action", "choices_by": options}])


def _changes(request, args):
    current = native._state(request)
    action, item = args["action"], args["item"]
    if action == "period":
        value = native.preferences._validate("today_days", item)
        return current, {"today_days": value}
    template = action in {"pin_template", "unpin_template"}
    allowed = projection.template_choices(request) if template else projection.CARDS
    if item not in allowed:
        raise product_error(403, "today_item_unavailable", "Choose a currently accessible card or template.")
    key = "template_favorites" if template else "today_cards"
    values = list(current["values"][key])
    if action in {"hide", "unpin_template"}:
        values = [value for value in values if value != item]
    elif action in {"show", "pin_template"} and item not in values:
        values.append(item)
    elif action in {"move_up", "move_down"} and item in values:
        index = values.index(item)
        target = index + (-1 if action == "move_up" else 1)
        if 0 <= target < len(values):
            values[index], values[target] = values[target], values[index]
    return current, {key: values}


def prepare(request, selection, arguments):
    state, changes = _changes(request, arguments)
    return Preview("Save this personal layout. Work continues and mandatory decisions remain available.",
        [{"field": key.replace("_", " "), "before": state["values"][key], "after": value} for key, value in changes.items()],
        {"revision": state["revision"], "context": state["context"], "scope": "personal", "thread": None, "changes": changes})


def execute(request, selection, arguments, review, operation_id):
    import json

    from .product_operations import Outcome
    _changes(request, arguments)
    response = native.update_preferences(request, native.PreferenceUpdate(context=review["context"],
        expected_revision=review["revision"], changes=review["changes"], operation_id=operation_id))
    state = json.loads(response.body)
    return Outcome("confirmed", "Your Today layout was saved. Refresh Today to see current work in this layout.",
                   {key: state["values"][key] for key in review["changes"]})


def read(request, selection, arguments):
    state = native._state(request)
    return Preview("Current native work projections, with source availability and observation time.",
                   native=projection.project(request, native._app()._world(), state))


def entries():
    pages = ("/today", "/preferences")
    return [Adapter("today.status", "Show my daily work", "preferences", "/today", pages, EmptyInput, snapshot, read),
            Adapter("today.layout", "Arrange my daily work", "preferences", "/today", pages, Layout, snapshot, prepare, execute, preferences.recover)]
